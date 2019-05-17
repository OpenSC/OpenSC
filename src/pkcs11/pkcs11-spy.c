/*
 * Copyright (C) 2015 Mathias Brossard <mathias@brossard.org>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307,
 * USA
 */

#include "config.h"

#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#include <winreg.h>
#include <limits.h>
#else
#include <sys/time.h>
#include <time.h>
#endif

#define CRYPTOKI_EXPORTS
#include "pkcs11-display.h"
#include "common/libpkcs11.h"

#define __PASTE(x,y)      x##y

/* Declare all spy_* Cryptoki function */

/* Spy Module Function List */
static CK_FUNCTION_LIST_PTR pkcs11_spy = NULL;
/* Real Module Function List */
static CK_FUNCTION_LIST_PTR po = NULL;
/* Dynamic Module Handle */
static void *modhandle = NULL;
/* Spy module output */
static FILE *spy_output = NULL;

/* Inits the spy. If successful, po != NULL */
static CK_RV
init_spy(void)
{
	const char *output, *module;
	CK_RV rv = CKR_OK;
#ifdef _WIN32
        char temp_path[PATH_MAX], expanded_path[PATH_MAX];
        DWORD temp_len, expanded_len;
        long rc;
        HKEY hKey;
#endif

	/* Allocates and initializes the pkcs11_spy structure */
	pkcs11_spy = malloc(sizeof(CK_FUNCTION_LIST));
	if (pkcs11_spy) {
		/* with our own pkcs11.h we need to maintain this ourself */
		pkcs11_spy->version.major = 2;
		pkcs11_spy->version.minor = 11;
		pkcs11_spy->C_Initialize = C_Initialize;
		pkcs11_spy->C_Finalize = C_Finalize;
		pkcs11_spy->C_GetInfo = C_GetInfo;
		pkcs11_spy->C_GetFunctionList = C_GetFunctionList;
		pkcs11_spy->C_GetSlotList = C_GetSlotList;
		pkcs11_spy->C_GetSlotInfo = C_GetSlotInfo;
		pkcs11_spy->C_GetTokenInfo = C_GetTokenInfo;
		pkcs11_spy->C_GetMechanismList = C_GetMechanismList;
		pkcs11_spy->C_GetMechanismInfo = C_GetMechanismInfo;
		pkcs11_spy->C_InitToken = C_InitToken;
		pkcs11_spy->C_InitPIN = C_InitPIN;
		pkcs11_spy->C_SetPIN = C_SetPIN;
		pkcs11_spy->C_OpenSession = C_OpenSession;
		pkcs11_spy->C_CloseSession = C_CloseSession;
		pkcs11_spy->C_CloseAllSessions = C_CloseAllSessions;
		pkcs11_spy->C_GetSessionInfo = C_GetSessionInfo;
		pkcs11_spy->C_GetOperationState = C_GetOperationState;
		pkcs11_spy->C_SetOperationState = C_SetOperationState;
		pkcs11_spy->C_Login = C_Login;
		pkcs11_spy->C_Logout = C_Logout;
		pkcs11_spy->C_CreateObject = C_CreateObject;
		pkcs11_spy->C_CopyObject = C_CopyObject;
		pkcs11_spy->C_DestroyObject = C_DestroyObject;
		pkcs11_spy->C_GetObjectSize = C_GetObjectSize;
		pkcs11_spy->C_GetAttributeValue = C_GetAttributeValue;
		pkcs11_spy->C_SetAttributeValue = C_SetAttributeValue;
		pkcs11_spy->C_FindObjectsInit = C_FindObjectsInit;
		pkcs11_spy->C_FindObjects = C_FindObjects;
		pkcs11_spy->C_FindObjectsFinal = C_FindObjectsFinal;
		pkcs11_spy->C_EncryptInit = C_EncryptInit;
		pkcs11_spy->C_Encrypt = C_Encrypt;
		pkcs11_spy->C_EncryptUpdate = C_EncryptUpdate;
		pkcs11_spy->C_EncryptFinal = C_EncryptFinal;
		pkcs11_spy->C_DecryptInit = C_DecryptInit;
		pkcs11_spy->C_Decrypt = C_Decrypt;
		pkcs11_spy->C_DecryptUpdate = C_DecryptUpdate;
		pkcs11_spy->C_DecryptFinal = C_DecryptFinal;
		pkcs11_spy->C_DigestInit = C_DigestInit;
		pkcs11_spy->C_Digest = C_Digest;
		pkcs11_spy->C_DigestUpdate = C_DigestUpdate;
		pkcs11_spy->C_DigestKey = C_DigestKey;
		pkcs11_spy->C_DigestFinal = C_DigestFinal;
		pkcs11_spy->C_SignInit = C_SignInit;
		pkcs11_spy->C_Sign = C_Sign;
		pkcs11_spy->C_SignUpdate = C_SignUpdate;
		pkcs11_spy->C_SignFinal = C_SignFinal;
		pkcs11_spy->C_SignRecoverInit = C_SignRecoverInit;
		pkcs11_spy->C_SignRecover = C_SignRecover;
		pkcs11_spy->C_VerifyInit = C_VerifyInit;
		pkcs11_spy->C_Verify = C_Verify;
		pkcs11_spy->C_VerifyUpdate = C_VerifyUpdate;
		pkcs11_spy->C_VerifyFinal = C_VerifyFinal;
		pkcs11_spy->C_VerifyRecoverInit = C_VerifyRecoverInit;
		pkcs11_spy->C_VerifyRecover = C_VerifyRecover;
		pkcs11_spy->C_DigestEncryptUpdate = C_DigestEncryptUpdate;
		pkcs11_spy->C_DecryptDigestUpdate = C_DecryptDigestUpdate;
		pkcs11_spy->C_SignEncryptUpdate = C_SignEncryptUpdate;
		pkcs11_spy->C_DecryptVerifyUpdate = C_DecryptVerifyUpdate;
		pkcs11_spy->C_GenerateKey = C_GenerateKey;
		pkcs11_spy->C_GenerateKeyPair = C_GenerateKeyPair;
		pkcs11_spy->C_WrapKey = C_WrapKey;
		pkcs11_spy->C_UnwrapKey = C_UnwrapKey;
		pkcs11_spy->C_DeriveKey = C_DeriveKey;
		pkcs11_spy->C_SeedRandom = C_SeedRandom;
		pkcs11_spy->C_GenerateRandom = C_GenerateRandom;
		pkcs11_spy->C_GetFunctionStatus = C_GetFunctionStatus;
		pkcs11_spy->C_CancelFunction = C_CancelFunction;
		pkcs11_spy->C_WaitForSlotEvent = C_WaitForSlotEvent;
	}
	else {
		return CKR_HOST_MEMORY;
	}

	/*
	 * Don't use getenv() as the last parameter for scconf_get_str(),
	 * as we want to be able to override configuration file via
	 * environment variables
	 */
	output = getenv("PKCS11SPY_OUTPUT");
	if (output)
		spy_output = fopen(output, "a");

#ifdef _WIN32
	if (!spy_output) {
		/* try for the machine version first, as we may be running
		 * without a user during login
		 */
		rc = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "Software\\OpenSC Project\\PKCS11-Spy", 0, KEY_QUERY_VALUE, &hKey );
		if (rc != ERROR_SUCCESS )
			rc = RegOpenKeyEx( HKEY_CURRENT_USER, "Software\\OpenSC Project\\PKCS11-Spy", 0, KEY_QUERY_VALUE, &hKey );

		if( rc == ERROR_SUCCESS ) {
			temp_len = PATH_MAX;
			rc = RegQueryValueEx( hKey, "Output", NULL, NULL, (LPBYTE) temp_path, &temp_len);
			if (rc == ERROR_SUCCESS)   {
				expanded_len = PATH_MAX;
				expanded_len = ExpandEnvironmentStrings(temp_path, expanded_path, expanded_len);
				if (expanded_len > 0)   {
					memcpy(temp_path, expanded_path, PATH_MAX);
					temp_len = expanded_len;
				}
			}

			if( (rc == ERROR_SUCCESS) && (temp_len < PATH_MAX) )
				output = temp_path;
			RegCloseKey( hKey );
		}

		spy_output = fopen(output, "a");
	}
#endif
	if (!spy_output)
		spy_output = stderr;

	fprintf(spy_output, "\n\n*************** OpenSC PKCS#11 spy *****************\n");

	module = getenv("PKCS11SPY");
#ifdef _WIN32
	if (!module) {
		/* try for the machine version first, as we may be running
		 * without a user during login
		 */
		rc = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "Software\\OpenSC Project\\PKCS11-Spy",
				0, KEY_QUERY_VALUE, &hKey );
		if (rc != ERROR_SUCCESS)
			rc = RegOpenKeyEx( HKEY_CURRENT_USER, "Software\\OpenSC Project\\PKCS11-Spy",
					0, KEY_QUERY_VALUE, &hKey );

		if (rc == ERROR_SUCCESS) {
			temp_len = PATH_MAX;
			rc = RegQueryValueEx( hKey, "Module", NULL, NULL, (LPBYTE) temp_path, &temp_len);
			if (rc == ERROR_SUCCESS)   {
				expanded_len = PATH_MAX;
				expanded_len = ExpandEnvironmentStrings(temp_path, expanded_path, expanded_len);
				if (expanded_len > 0)   {
					memcpy(temp_path, expanded_path, PATH_MAX);
					temp_len = expanded_len;
				}
			}

			if( (rc == ERROR_SUCCESS) && (temp_len < PATH_MAX) )
				module = temp_path;
			RegCloseKey( hKey );
		}
	}
#endif
	if (module == NULL) {
		fprintf(spy_output, "Error: no module specified. Please set PKCS11SPY environment.\n");
		free(pkcs11_spy);
		return CKR_DEVICE_ERROR;
	}

	modhandle = C_LoadModule(module, &po);
	if (modhandle && po) {
		fprintf(spy_output, "Loaded: \"%s\"\n", module);
	}
	else {
		po = NULL;
		free(pkcs11_spy);
		rv = CKR_GENERAL_ERROR;
	}

	return rv;
}


static void
enter(const char *function)
{
	static int count = 0;
#ifdef _WIN32
	SYSTEMTIME st;
#else
	struct tm *tm;
	struct timeval tv;
	char time_string[40];
#endif

	fprintf(spy_output, "\n%d: %s\n", count++, function);
#ifdef _WIN32
        GetLocalTime(&st);
        fprintf(spy_output, "%i-%02i-%02i %02i:%02i:%02i.%03i\n", st.wYear, st.wMonth, st.wDay,
			st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
#else
	gettimeofday (&tv, NULL);
	tm = localtime (&tv.tv_sec);
	strftime (time_string, sizeof(time_string), "%F %H:%M:%S", tm);
	fprintf(spy_output, "%s.%03ld\n", time_string, (long)tv.tv_usec / 1000);
#endif

}

static CK_RV
retne(CK_RV rv)
{
	fprintf(spy_output, "Returned:  %ld %s\n", (unsigned long) rv, lookup_enum ( RV_T, rv ));
	fflush(spy_output);
	return rv;
}


static void
spy_dump_string_in(const char *name, CK_VOID_PTR data, CK_ULONG size)
{
	fprintf(spy_output, "[in] %s ", name);
	print_generic(spy_output, 0, data, size, NULL);
}

static void
spy_dump_string_out(const char *name, CK_VOID_PTR data, CK_ULONG size)
{
	fprintf(spy_output, "[out] %s ", name);
	print_generic(spy_output, 0, data, size, NULL);
}

static void
spy_dump_ulong_in(const char *name, CK_ULONG value)
{
	fprintf(spy_output, "[in] %s = 0x%lx\n", name, value);
}

static void
spy_dump_ulong_out(const char *name, CK_ULONG value)
{
	fprintf(spy_output, "[out] %s = 0x%lx\n", name, value);
}

static void
spy_dump_desc_out(const char *name)
{
  fprintf(spy_output, "[out] %s: \n", name);
}

static void
spy_dump_array_out(const char *name, CK_ULONG size)
{
	fprintf(spy_output, "[out] %s[%ld]: \n", name, size);
}

static void
spy_attribute_req_in(const char *name, CK_ATTRIBUTE_PTR pTemplate,
			  CK_ULONG  ulCount)
{
	fprintf(spy_output, "[in] %s[%ld]: \n", name, ulCount);
	print_attribute_list_req(spy_output, pTemplate, ulCount);
}

static void
spy_attribute_list_in(const char *name, CK_ATTRIBUTE_PTR pTemplate,
			  CK_ULONG  ulCount)
{
	fprintf(spy_output, "[in] %s[%ld]: \n", name, ulCount);
	print_attribute_list(spy_output, pTemplate, ulCount);
}

static void
spy_attribute_list_out(const char *name, CK_ATTRIBUTE_PTR pTemplate,
			  CK_ULONG  ulCount)
{
	fprintf(spy_output, "[out] %s[%ld]: \n", name, ulCount);
	print_attribute_list(spy_output, pTemplate, ulCount);
}

static void
print_ptr_in(const char *name, CK_VOID_PTR ptr)
{
 	fprintf(spy_output, "[in] %s = %p\n", name, ptr);
}

CK_RV C_GetFunctionList
(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (po == NULL) {
		CK_RV rv = init_spy();
		if (rv != CKR_OK)
			return rv;
	}

	enter("C_GetFunctionList");
	*ppFunctionList = pkcs11_spy;
	return retne(CKR_OK);
}

CK_RV
C_Initialize(CK_VOID_PTR pInitArgs)
{
	CK_RV rv;

	if (po == NULL) {
		rv = init_spy();
		if (rv != CKR_OK)
			return rv;
	}

	enter("C_Initialize");
	print_ptr_in("pInitArgs", pInitArgs);

	if (pInitArgs) {
		CK_C_INITIALIZE_ARGS *ptr = pInitArgs;
		fprintf(spy_output, "     flags: %ld\n", ptr->flags);
		if (ptr->flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS)
			fprintf(spy_output, "       CKF_LIBRARY_CANT_CREATE_OS_THREADS\n");
		if (ptr->flags & CKF_OS_LOCKING_OK)
			fprintf(spy_output, "       CKF_OS_LOCKING_OK\n");
	}

	rv = po->C_Initialize(pInitArgs);
	return retne(rv);
}

CK_RV
C_Finalize(CK_VOID_PTR pReserved)
{
	CK_RV rv;

	enter("C_Finalize");
	rv = po->C_Finalize(pReserved);
	return retne(rv);
}

CK_RV
C_GetInfo(CK_INFO_PTR pInfo)
{
	CK_RV rv;

	enter("C_GetInfo");
	rv = po->C_GetInfo(pInfo);
	if(rv == CKR_OK) {
		spy_dump_desc_out("pInfo");
		print_ck_info(spy_output, pInfo);
	}
	return retne(rv);
}

CK_RV
C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
		CK_ULONG_PTR pulCount)
{
	CK_RV rv;

	enter("C_GetSlotList");
	spy_dump_ulong_in("tokenPresent", tokenPresent);
	rv = po->C_GetSlotList(tokenPresent, pSlotList, pulCount);
	if(rv == CKR_OK) {
		spy_dump_desc_out("pSlotList");
		print_slot_list(spy_output, pSlotList, *pulCount);
		spy_dump_ulong_out("*pulCount", *pulCount);
	}
	return retne(rv);
}

CK_RV
C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	CK_RV rv;

	enter("C_GetSlotInfo");
	spy_dump_ulong_in("slotID", slotID);
	rv = po->C_GetSlotInfo(slotID, pInfo);
	if(rv == CKR_OK) {
		spy_dump_desc_out("pInfo");
		print_slot_info(spy_output, pInfo);
	}
	return retne(rv);
}

CK_RV
C_GetTokenInfo(CK_SLOT_ID slotID,
			 CK_TOKEN_INFO_PTR pInfo)
{
	CK_RV rv;

	enter("C_GetTokenInfo");
	spy_dump_ulong_in("slotID", slotID);
	rv = po->C_GetTokenInfo(slotID, pInfo);
	if(rv == CKR_OK) {
		spy_dump_desc_out("pInfo");
		print_token_info(spy_output, pInfo);
	}
	return retne(rv);
}

CK_RV
C_GetMechanismList(CK_SLOT_ID  slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
		CK_ULONG_PTR  pulCount)
{
	CK_RV rv;

	enter("C_GetMechanismList");
	spy_dump_ulong_in("slotID", slotID);
	rv = po->C_GetMechanismList(slotID, pMechanismList, pulCount);
	if(rv == CKR_OK) {
		spy_dump_array_out("pMechanismList", *pulCount);
		print_mech_list(spy_output, pMechanismList, *pulCount);
	}
	return retne(rv);
}

CK_RV
C_GetMechanismInfo(CK_SLOT_ID  slotID, CK_MECHANISM_TYPE type,
		CK_MECHANISM_INFO_PTR pInfo)
{
	CK_RV rv;
	const char *name = lookup_enum(MEC_T, type);

	enter("C_GetMechanismInfo");
	spy_dump_ulong_in("slotID", slotID);
	if (name)
		fprintf(spy_output, "%30s \n", name);
	else
		fprintf(spy_output, " Unknown Mechanism (%08lx)  \n", type);

	rv = po->C_GetMechanismInfo(slotID, type, pInfo);
	if(rv == CKR_OK) {
		spy_dump_desc_out("pInfo");
		print_mech_info(spy_output, type, pInfo);
	}
	return retne(rv);
}

CK_RV
C_InitToken (CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
		CK_UTF8CHAR_PTR pLabel)
{
	CK_RV rv;

	enter("C_InitToken");
	spy_dump_ulong_in("slotID", slotID);
	spy_dump_string_in("pPin[ulPinLen]", pPin, ulPinLen);
	spy_dump_string_in("pLabel[32]", pLabel, 32);
	rv = po->C_InitToken (slotID, pPin, ulPinLen, pLabel);
	return retne(rv);
}

CK_RV
C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG  ulPinLen)
{
	CK_RV rv;

	enter("C_InitPIN");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pPin[ulPinLen]", pPin, ulPinLen);
	rv = po->C_InitPIN(hSession, pPin, ulPinLen);
	return retne(rv);
}

CK_RV
C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG  ulOldLen,
		   CK_UTF8CHAR_PTR pNewPin, CK_ULONG  ulNewLen)
{
	CK_RV rv;

	enter("C_SetPIN");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pOldPin[ulOldLen]", pOldPin, ulOldLen);
	spy_dump_string_in("pNewPin[ulNewLen]", pNewPin, ulNewLen);
	rv = po->C_SetPIN(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
	return retne(rv);
}

CK_RV
C_OpenSession(CK_SLOT_ID  slotID, CK_FLAGS  flags, CK_VOID_PTR  pApplication,
		CK_NOTIFY  Notify, CK_SESSION_HANDLE_PTR phSession)
{
	CK_RV rv;

	enter("C_OpenSession");
	spy_dump_ulong_in("slotID", slotID);
	spy_dump_ulong_in("flags", flags);
	fprintf(spy_output, "pApplication=%p\n", pApplication);
	fprintf(spy_output, "Notify=%p\n", (void *)Notify);
	rv = po->C_OpenSession(slotID, flags, pApplication, Notify, phSession);
	spy_dump_ulong_out("*phSession", *phSession);
	return retne(rv);
}

CK_RV
C_CloseSession(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;

	enter("C_CloseSession");
	spy_dump_ulong_in("hSession", hSession);
	rv = po->C_CloseSession(hSession);
	return retne(rv);
}

CK_RV
C_CloseAllSessions(CK_SLOT_ID slotID)
{
	CK_RV rv;
	enter("C_CloseAllSessions");
	spy_dump_ulong_in("slotID", slotID);
	rv = po->C_CloseAllSessions(slotID);
	return retne(rv);
}

CK_RV
C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	CK_RV rv;

	enter("C_GetSessionInfo");
	spy_dump_ulong_in("hSession", hSession);
	rv = po->C_GetSessionInfo(hSession, pInfo);
	if(rv == CKR_OK) {
		spy_dump_desc_out("pInfo");
		print_session_info(spy_output, pInfo);
	}
	return retne(rv);
}

CK_RV
C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
		CK_ULONG_PTR pulOperationStateLen)
{
	CK_RV rv;

	enter("C_GetOperationState");
	spy_dump_ulong_in("hSession", hSession);
	rv = po->C_GetOperationState(hSession, pOperationState, pulOperationStateLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pOperationState[*pulOperationStateLen]", pOperationState, *pulOperationStateLen);
	return retne(rv);
}

CK_RV
C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG  ulOperationStateLen,
		CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	CK_RV rv;

	enter("SetOperationState");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pOperationState[ulOperationStateLen]", pOperationState, ulOperationStateLen);
	spy_dump_ulong_in("hEncryptionKey", hEncryptionKey);
	spy_dump_ulong_in("hAuthenticationKey", hAuthenticationKey);
	rv = po->C_SetOperationState(hSession, pOperationState, ulOperationStateLen,
			hEncryptionKey, hAuthenticationKey);
	return retne(rv);
}

CK_RV
C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
		CK_UTF8CHAR_PTR pPin, CK_ULONG  ulPinLen)
{
	CK_RV rv;

	enter("C_Login");
	spy_dump_ulong_in("hSession", hSession);
	fprintf(spy_output, "[in] userType = %s\n",
			lookup_enum(USR_T, userType));
	spy_dump_string_in("pPin[ulPinLen]", pPin, ulPinLen);
	rv = po->C_Login(hSession, userType, pPin, ulPinLen);
	return retne(rv);
}

CK_RV
C_Logout(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	enter("C_Logout");
	spy_dump_ulong_in("hSession", hSession);
	rv = po->C_Logout(hSession);
	return retne(rv);
}

CK_RV
C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG  ulCount,
		CK_OBJECT_HANDLE_PTR phObject)
{
	CK_RV rv;

	enter("C_CreateObject");
	spy_dump_ulong_in("hSession", hSession);
	spy_attribute_list_in("pTemplate", pTemplate, ulCount);
	rv = po->C_CreateObject(hSession, pTemplate, ulCount, phObject);
	if (rv == CKR_OK)
		spy_dump_ulong_out("*phObject", *phObject);
	return retne(rv);
}

CK_RV
C_CopyObject(CK_SESSION_HANDLE hSession,
		       CK_OBJECT_HANDLE hObject,
		       CK_ATTRIBUTE_PTR pTemplate,
		       CK_ULONG  ulCount,
		       CK_OBJECT_HANDLE_PTR phNewObject)
{
	CK_RV rv;

	enter("C_CopyObject");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_ulong_in("hObject", hObject);
	spy_attribute_list_in("pTemplate", pTemplate, ulCount);
	rv = po->C_CopyObject(hSession, hObject, pTemplate, ulCount, phNewObject);
	if (rv == CKR_OK)
		spy_dump_ulong_out("*phNewObject", *phNewObject);

	return retne(rv);
}

CK_RV
C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	CK_RV rv;

	enter("C_DestroyObject");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_ulong_in("hObject", hObject);
	rv = po->C_DestroyObject(hSession, hObject);
	return retne(rv);
}

CK_RV
C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	CK_RV rv;

	enter("C_GetObjectSize");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_ulong_in("hObject", hObject);
	rv = po->C_GetObjectSize(hSession, hObject, pulSize);
	if (rv == CKR_OK)
		spy_dump_ulong_out("*pulSize", *pulSize);

	return retne(rv);
}

CK_RV
C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG  ulCount)
{
	CK_RV rv;

	enter("C_GetAttributeValue");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_ulong_in("hObject", hObject);
	spy_attribute_req_in("pTemplate", pTemplate, ulCount);
	/* PKCS#11 says:
	 * ``Note that the error codes CKR_ATTRIBUTE_SENSITIVE,
	 *   CKR_ATTRIBUTE_TYPE_INVALID, and CKR_BUFFER_TOO_SMALL do not denote
	 *   true errors for C_GetAttributeValue.''
	 * That's why we ignore these error codes, because we want to display
	 * all other attributes anyway (they may have been returned correctly)
	 */
	rv = po->C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
	if (rv == CKR_OK || rv == CKR_ATTRIBUTE_SENSITIVE ||
			rv == CKR_ATTRIBUTE_TYPE_INVALID || rv == CKR_BUFFER_TOO_SMALL)
		spy_attribute_list_out("pTemplate", pTemplate, ulCount);
	return retne(rv);
}

CK_RV
C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG  ulCount)
{
	CK_RV rv;

	enter("C_SetAttributeValue");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_ulong_in("hObject", hObject);
	spy_attribute_list_in("pTemplate", pTemplate, ulCount);
	rv = po->C_SetAttributeValue(hSession, hObject, pTemplate, ulCount);
	return retne(rv);
}

CK_RV
C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG  ulCount)
{
	CK_RV rv;

	enter("C_FindObjectsInit");
	spy_dump_ulong_in("hSession", hSession);
	spy_attribute_list_in("pTemplate", pTemplate, ulCount);
	rv = po->C_FindObjectsInit(hSession, pTemplate, ulCount);
	return retne(rv);
}

CK_RV
C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG  ulMaxObjectCount,
		CK_ULONG_PTR  pulObjectCount)
{
	CK_RV rv;

	enter("C_FindObjects");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_ulong_in("ulMaxObjectCount", ulMaxObjectCount);
	rv = po->C_FindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
	if (rv == CKR_OK) {
		CK_ULONG          i;
		spy_dump_ulong_out("ulObjectCount", *pulObjectCount);
		for (i = 0; i < *pulObjectCount; i++)
			fprintf(spy_output, "Object 0x%lx matches\n", phObject[i]);
	}
	return retne(rv);
}

CK_RV
C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;

	enter("C_FindObjectsFinal");
	spy_dump_ulong_in("hSession", hSession);
	rv = po->C_FindObjectsFinal(hSession);
	return retne(rv);
}

CK_RV
C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	enter("C_EncryptInit");
	spy_dump_ulong_in("hSession", hSession);
	fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
	switch (pMechanism->mechanism) {
	case CKM_AES_GCM:
		if (pMechanism->pParameter != NULL) {
			CK_GCM_PARAMS *param =
				(CK_GCM_PARAMS *) pMechanism->pParameter;
			spy_dump_string_in("pIv[ulIvLen]",
				param->pIv, param->ulIvLen);
			spy_dump_ulong_in("ulIvBits", param->ulIvBits);
			spy_dump_string_in("pAAD[ulAADLen]",
				param->pAAD, param->ulAADLen);
			fprintf(spy_output, "pMechanism->pParameter->ulTagBits=%lu\n", param->ulTagBits);
		} else {
			fprintf(spy_output, "Parameters block for %s is empty...\n",
				lookup_enum(MEC_T, pMechanism->mechanism));
		}
		break;
	default:
		spy_dump_string_in("pParameter[ulParameterLen]", pMechanism->pParameter, pMechanism->ulParameterLen);
		break;
	}
	spy_dump_ulong_in("hKey", hKey);
	rv = po->C_EncryptInit(hSession, pMechanism, hKey);
	return retne(rv);
}

CK_RV
C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG  ulDataLen,
		CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	CK_RV rv;

	enter("C_Encrypt");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
	rv = po->C_Encrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pEncryptedData[*pulEncryptedDataLen]", pEncryptedData, *pulEncryptedDataLen);
	return retne(rv);
}

CK_RV
C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG  ulPartLen,
		CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_RV rv;

	enter("C_EncryptUpdate");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
	rv = po->C_EncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pEncryptedPart[*pulEncryptedPartLen]", pEncryptedPart, *pulEncryptedPartLen);
	return retne(rv);
}

CK_RV
C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	CK_RV rv;

	enter("C_EncryptFinal");
	spy_dump_ulong_in("hSession", hSession);
	rv = po->C_EncryptFinal(hSession, pLastEncryptedPart, pulLastEncryptedPartLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pLastEncryptedPart[*pulLastEncryptedPartLen]", pLastEncryptedPart,
				*pulLastEncryptedPartLen);

	return retne(rv);
}

CK_RV
C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	enter("C_DecryptInit");
	spy_dump_ulong_in("hSession", hSession);
	fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
	switch (pMechanism->mechanism) {
	case CKM_RSA_PKCS_OAEP:
		if (pMechanism->pParameter != NULL) {
 			CK_RSA_PKCS_OAEP_PARAMS *param =
				(CK_RSA_PKCS_OAEP_PARAMS *) pMechanism->pParameter;
			fprintf(spy_output, "pMechanism->pParameter->hashAlg=%s\n",
				lookup_enum(MEC_T, param->hashAlg));
			fprintf(spy_output, "pMechanism->pParameter->mgf=%s\n",
				lookup_enum(MGF_T, param->mgf));
			fprintf(spy_output, "pMechanism->pParameter->source=%lu\n", param->source);
			spy_dump_string_out("pSourceData[ulSourceDalaLen]", 
				param->pSourceData, param->ulSourceDataLen);
		} else {
			fprintf(spy_output, "Parameters block for %s is empty...\n",
				lookup_enum(MEC_T, pMechanism->mechanism));
		}
		break;
	default:
		spy_dump_string_in("pParameter[ulParameterLen]", pMechanism->pParameter, pMechanism->ulParameterLen);
		break;
	}
	spy_dump_ulong_in("hKey", hKey);
	rv = po->C_DecryptInit(hSession, pMechanism, hKey);
	return retne(rv);
}

CK_RV
C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG  ulEncryptedDataLen,
		CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_RV rv;

	enter("C_Decrypt");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pEncryptedData[ulEncryptedDataLen]", pEncryptedData, ulEncryptedDataLen);
	rv = po->C_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pData[*pulDataLen]", pData, *pulDataLen);

	return retne(rv);
}

CK_RV
C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG  ulEncryptedPartLen,
		CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_RV rv;

	enter("C_DecryptUpdate");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pEncryptedPart[ulEncryptedPartLen]", pEncryptedPart, ulEncryptedPartLen);
	rv = po->C_DecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pPart[*pulPartLen]", pPart, *pulPartLen);

	return retne(rv);
}

CK_RV
C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	CK_RV rv;

	enter("C_DecryptFinal");
	spy_dump_ulong_in("hSession", hSession);
	rv = po->C_DecryptFinal(hSession, pLastPart, pulLastPartLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pLastPart[*pulLastPartLen]", pLastPart, *pulLastPartLen);

	return retne(rv);
}

CK_RV
C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	CK_RV rv;

	enter("C_DigestInit");
	spy_dump_ulong_in("hSession", hSession);
	fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
	rv = po->C_DigestInit(hSession, pMechanism);
	return retne(rv);
}

CK_RV
C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG  ulDataLen,
		CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	CK_RV rv;

	enter("C_Digest");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
	rv = po->C_Digest(hSession, pData, ulDataLen, pDigest, pulDigestLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pDigest[*pulDigestLen]", pDigest, *pulDigestLen);

	return retne(rv);
}

CK_RV
C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG  ulPartLen)
{
	CK_RV rv;

	enter("C_DigestUpdate");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
	rv = po->C_DigestUpdate(hSession, pPart, ulPartLen);
	return retne(rv);
}

CK_RV
C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	enter("C_DigestKey");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_ulong_in("hKey", hKey);
	rv = po->C_DigestKey(hSession, hKey);
	return retne(rv);
}

CK_RV
C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	CK_RV rv;

	enter("C_DigestFinal");
	spy_dump_ulong_in("hSession", hSession);
	rv = po->C_DigestFinal(hSession, pDigest, pulDigestLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pDigest[*pulDigestLen]", pDigest, *pulDigestLen);

	return retne(rv);
}

CK_RV
C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	enter("C_SignInit");
	spy_dump_ulong_in("hSession", hSession);
	fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
	switch (pMechanism->mechanism) {
	case CKM_RSA_PKCS_PSS:
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
	case CKM_SHA384_RSA_PKCS_PSS:
	case CKM_SHA512_RSA_PKCS_PSS:
		if (pMechanism->pParameter != NULL) {
			CK_RSA_PKCS_PSS_PARAMS *param =
				(CK_RSA_PKCS_PSS_PARAMS *) pMechanism->pParameter;
			fprintf(spy_output, "pMechanism->pParameter->hashAlg=%s\n",
				lookup_enum(MEC_T, param->hashAlg));
			fprintf(spy_output, "pMechanism->pParameter->mgf=%s\n",
				lookup_enum(MGF_T, param->mgf));
			fprintf(spy_output, "pMechanism->pParameter->sLen=%lu\n",
				param->sLen);
		} else {
			fprintf(spy_output, "Parameters block for %s is empty...\n",
				lookup_enum(MEC_T, pMechanism->mechanism));
		}
		break;
	}
	spy_dump_ulong_in("hKey", hKey);
	rv = po->C_SignInit(hSession, pMechanism, hKey);
	return retne(rv);
}

CK_RV
C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG  ulDataLen,
		CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;

	enter("C_Sign");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
	rv = po->C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pSignature[*pulSignatureLen]", pSignature, *pulSignatureLen);

	return retne(rv);
}

CK_RV
C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG  ulPartLen)
{
	CK_RV rv;

	enter("C_SignUpdate");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
	rv = po->C_SignUpdate(hSession, pPart, ulPartLen);
	return retne(rv);
}

CK_RV
C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;

	enter("C_SignFinal");
	spy_dump_ulong_in("hSession", hSession);
	rv = po->C_SignFinal(hSession, pSignature, pulSignatureLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pSignature[*pulSignatureLen]", pSignature, *pulSignatureLen);

	return retne(rv);
}

CK_RV
C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	enter("C_SignRecoverInit");
	spy_dump_ulong_in("hSession", hSession);
	fprintf(spy_output, "pMechanism->type=%s\n",
			lookup_enum(MEC_T, pMechanism->mechanism));
	spy_dump_ulong_in("hKey", hKey);
	rv = po->C_SignRecoverInit(hSession, pMechanism, hKey);
	return retne(rv);
}

CK_RV
C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG  ulDataLen,
		CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;

	enter("C_SignRecover");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
	rv = po->C_SignRecover(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pSignature[*pulSignatureLen]", pSignature, *pulSignatureLen);
	return retne(rv);
}

CK_RV
C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	enter("C_VerifyInit");
	spy_dump_ulong_in("hSession", hSession);
	fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
	spy_dump_ulong_in("hKey", hKey);
	rv = po->C_VerifyInit(hSession, pMechanism, hKey);
	return retne(rv);
}

CK_RV
C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG  ulDataLen,
		CK_BYTE_PTR pSignature, CK_ULONG  ulSignatureLen)
{
	CK_RV rv;

	enter("C_Verify");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
	spy_dump_string_in("pSignature[ulSignatureLen]", pSignature, ulSignatureLen);
	rv = po->C_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
	return retne(rv);
}

CK_RV
C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG  ulPartLen)
{
	CK_RV rv;

	enter("C_VerifyUpdate");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
	rv = po->C_VerifyUpdate(hSession, pPart, ulPartLen);
	return retne(rv);
}

CK_RV
C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG  ulSignatureLen)
{
	CK_RV rv;

	enter("C_VerifyFinal");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pSignature[ulSignatureLen]", pSignature, ulSignatureLen);
	rv = po->C_VerifyFinal(hSession, pSignature, ulSignatureLen);
	return retne(rv);
}


CK_RV
C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	enter("C_VerifyRecoverInit");
	spy_dump_ulong_in("hSession", hSession);
	fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
	spy_dump_ulong_in("hKey", hKey);
	rv = po->C_VerifyRecoverInit(hSession, pMechanism, hKey);
	return retne(rv);
}

CK_RV
C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG  ulSignatureLen,
		CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_RV rv;

	enter("C_VerifyRecover");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pSignature[ulSignatureLen]", pSignature, ulSignatureLen);
	rv = po->C_VerifyRecover(hSession, pSignature, ulSignatureLen, pData, pulDataLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pData[*pulDataLen]", pData, *pulDataLen);
	return retne(rv);
}

CK_RV
C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG  ulPartLen,
		CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_RV rv;

	enter("C_DigestEncryptUpdate");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
	rv = po->C_DigestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pEncryptedPart[*pulEncryptedPartLen]", pEncryptedPart, *pulEncryptedPartLen);

	return retne(rv);
}

CK_RV
C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,CK_ULONG  ulEncryptedPartLen,
		CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_RV rv;

	enter("C_DecryptDigestUpdate");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pEncryptedPart[ulEncryptedPartLen]", pEncryptedPart, ulEncryptedPartLen);
	rv = po->C_DecryptDigestUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pPart[*pulPartLen]", pPart, *pulPartLen);
	return retne(rv);
}

CK_RV
C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG  ulPartLen,
		CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_RV rv;

	enter("C_SignEncryptUpdate");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
	rv = po->C_SignEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pEncryptedPart[*pulEncryptedPartLen]", pEncryptedPart, *pulEncryptedPartLen);

	return retne(rv);
}

CK_RV
C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG  ulEncryptedPartLen,
		CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_RV rv;

	enter("C_DecryptVerifyUpdate");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pEncryptedPart[ulEncryptedPartLen]", pEncryptedPart, ulEncryptedPartLen);
	rv = po->C_DecryptVerifyUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pPart[*pulPartLen]", pPart, *pulPartLen);

	return retne(rv);
}

CK_RV
C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG  ulCount,
		CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;

	enter("C_GenerateKey");
	spy_dump_ulong_in("hSession", hSession);
	fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
	spy_attribute_list_in("pTemplate", pTemplate, ulCount);
	rv = po->C_GenerateKey(hSession, pMechanism, pTemplate, ulCount, phKey);
	if (rv == CKR_OK)
		spy_dump_ulong_out("hKey", *phKey);

	return retne(rv);
}

CK_RV
C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG  ulPublicKeyAttributeCount,
		CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG  ulPrivateKeyAttributeCount,
		CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	CK_RV rv;

	enter("C_GenerateKeyPair");
	spy_dump_ulong_in("hSession", hSession);
	fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
	spy_attribute_list_in("pPublicKeyTemplate", pPublicKeyTemplate, ulPublicKeyAttributeCount);
	spy_attribute_list_in("pPrivateKeyTemplate", pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	rv = po->C_GenerateKeyPair(hSession, pMechanism,
			pPublicKeyTemplate, ulPublicKeyAttributeCount,
			pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
			phPublicKey, phPrivateKey);
	if (rv == CKR_OK)   {
		spy_dump_ulong_out("hPublicKey", *phPublicKey);
		spy_dump_ulong_out("hPrivateKey", *phPrivateKey);
	}
	return retne(rv);
}

CK_RV
C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
		CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	CK_RV rv;

	enter("C_WrapKey");
	spy_dump_ulong_in("hSession", hSession);
	fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
	spy_dump_ulong_in("hWrappingKey", hWrappingKey);
	spy_dump_ulong_in("hKey", hKey);
	rv = po->C_WrapKey(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen);
	if (rv == CKR_OK)
		spy_dump_string_out("pWrappedKey[*pulWrappedKeyLen]", pWrappedKey, *pulWrappedKeyLen);

	return retne(rv);
}

CK_RV
C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR  pWrappedKey, CK_ULONG  ulWrappedKeyLen,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG  ulAttributeCount,
		CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;

	enter("C_UnwrapKey");
	spy_dump_ulong_in("hSession", hSession);
	fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
	spy_dump_ulong_in("hUnwrappingKey", hUnwrappingKey);
	spy_dump_string_in("pWrappedKey[ulWrappedKeyLen]", pWrappedKey, ulWrappedKeyLen);
	spy_attribute_list_in("pTemplate", pTemplate, ulAttributeCount);
	rv = po->C_UnwrapKey(hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate,
			ulAttributeCount, phKey);
	if (rv == CKR_OK)
		spy_dump_ulong_out("hKey", *phKey);
	return retne(rv);
}

CK_RV
C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG  ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;

	enter("C_DeriveKey");
	spy_dump_ulong_in("hSession", hSession);
	fprintf(spy_output, "[in] pMechanism->type=%s\n",
		lookup_enum(MEC_T, pMechanism->mechanism));
	switch (pMechanism->mechanism) {
	case CKM_ECDH1_DERIVE:
	case CKM_ECDH1_COFACTOR_DERIVE:
		if (pMechanism->pParameter == NULL) {
			fprintf(spy_output, "[in] pMechanism->pParameter = NULL\n");
			break;
		}
		CK_ECDH1_DERIVE_PARAMS *param =
			(CK_ECDH1_DERIVE_PARAMS *) pMechanism->pParameter;
		fprintf(spy_output, "[in] pMechanism->pParameter = {\n\tkdf=%s\n",
			lookup_enum(CKD_T, param->kdf));
		fprintf(spy_output, "\tpSharedData[ulSharedDataLen] = ");
		print_generic(spy_output, 0, param->pSharedData,
			param->ulSharedDataLen, NULL);
		fprintf(spy_output, "\tpPublicData[ulPublicDataLen] = ");
		print_generic(spy_output, 0, param->pPublicData,
			param->ulPublicDataLen, NULL);
		fprintf(spy_output, "}\n");
		break;
	case CKM_ECMQV_DERIVE:
		if (pMechanism->pParameter == NULL) {
			fprintf(spy_output, "[in] pMechanism->pParameter = NULL\n");
			break;
		}
		CK_ECMQV_DERIVE_PARAMS *param2 =
			(CK_ECMQV_DERIVE_PARAMS *) pMechanism->pParameter;
		fprintf(spy_output, "[in] pMechanism->pParameter = {\n\tkdf=%s\n",
			lookup_enum(CKD_T, param2->kdf));
		fprintf(spy_output, "\tpSharedData[ulSharedDataLen] =");
		print_generic(spy_output, 0, param2->pSharedData,
			param2->ulSharedDataLen, NULL);
		fprintf(spy_output, "\tpPublicData[ulPublicDataLen] = ");
		print_generic(spy_output, 0, param2->pPublicData,
			param2->ulPublicDataLen, NULL);
		fprintf(spy_output, "\tulPrivateDataLen = %lu",
			param2->ulPrivateDataLen);
		fprintf(spy_output, "\thPrivateData = %lu", param2->hPrivateData);
		fprintf(spy_output, "\tpPublicData2[ulPublicDataLen2] = ");
		print_generic(spy_output, 0, param2->pPublicData2,
			param2->ulPublicDataLen2, NULL);
		fprintf(spy_output, "\tpublicKey = %lu", param2->publicKey);
		fprintf(spy_output, "}\n");
		break;
	}
	spy_dump_ulong_in("hBaseKey", hBaseKey);
	spy_attribute_list_in("pTemplate", pTemplate, ulAttributeCount);
	rv = po->C_DeriveKey(hSession, pMechanism, hBaseKey, pTemplate, ulAttributeCount, phKey);
	if (rv == CKR_OK)
		spy_dump_ulong_out("hKey", *phKey);

	return retne(rv);
}

CK_RV
C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG  ulSeedLen)
{
	CK_RV rv;

	enter("C_SeedRandom");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pSeed[ulSeedLen]", pSeed, ulSeedLen);
	rv = po->C_SeedRandom(hSession, pSeed, ulSeedLen);
	return retne(rv);
}

CK_RV
C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG  ulRandomLen)
{
	CK_RV rv;

	enter("C_GenerateRandom");
	spy_dump_ulong_in("hSession", hSession);
	rv = po->C_GenerateRandom(hSession, RandomData, ulRandomLen);
	if (rv == CKR_OK)
		spy_dump_string_out("RandomData[ulRandomLen]", RandomData, ulRandomLen);
	return retne(rv);
}

CK_RV
C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;

	enter("C_GetFunctionStatus");
	spy_dump_ulong_in("hSession", hSession);
	rv = po->C_GetFunctionStatus(hSession);
	return retne(rv);
}

CK_RV
C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;

	enter("C_CancelFunction");
	spy_dump_ulong_in("hSession", hSession);
	rv = po->C_CancelFunction(hSession);
	return retne(rv);
}

CK_RV
C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pRserved)
{
	CK_RV rv;

	enter("C_WaitForSlotEvent");
	spy_dump_ulong_in("flags", flags);
	rv = po->C_WaitForSlotEvent(flags, pSlot, pRserved);
	return retne(rv);
}
