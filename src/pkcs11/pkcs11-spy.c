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
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <winreg.h>
#include <limits.h>
#else
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <time.h>
#endif

#define CRYPTOKI_EXPORTS
#include "pkcs11-display.h"
#include "common/libpkcs11.h"

#define __PASTE(x,y)      x##y

/* Declare all spy_* Cryptoki function */

/* Spy Module Function List */
static CK_FUNCTION_LIST_PTR pkcs11_spy = NULL;
static CK_FUNCTION_LIST_3_0_PTR pkcs11_spy_3_0 = NULL;
/* Real Module Function List */
static CK_FUNCTION_LIST_3_0_PTR po = NULL;
/* Dynamic Module Handle */
static void *modhandle = NULL;
/* Spy module output */
static FILE *spy_output = NULL;

static void *
allocate_function_list(int v3)
{
	CK_FUNCTION_LIST_PTR list = NULL;
	CK_FUNCTION_LIST_3_0_PTR list_3_0 = NULL;

	if (v3) {
		list = malloc(sizeof(CK_FUNCTION_LIST_3_0));
	} else {
		list = malloc(sizeof(CK_FUNCTION_LIST));
	}
	if (list == NULL) {
		return NULL;
	}
	/* with our own pkcs11.h we need to maintain this ourself */
	list->version.major = 2;
	list->version.minor = 11;
	list->C_Initialize = C_Initialize;
	list->C_Finalize = C_Finalize;
	list->C_GetInfo = C_GetInfo;
	list->C_GetFunctionList = C_GetFunctionList;
	list->C_GetSlotList = C_GetSlotList;
	list->C_GetSlotInfo = C_GetSlotInfo;
	list->C_GetTokenInfo = C_GetTokenInfo;
	list->C_GetMechanismList = C_GetMechanismList;
	list->C_GetMechanismInfo = C_GetMechanismInfo;
	list->C_InitToken = C_InitToken;
	list->C_InitPIN = C_InitPIN;
	list->C_SetPIN = C_SetPIN;
	list->C_OpenSession = C_OpenSession;
	list->C_CloseSession = C_CloseSession;
	list->C_CloseAllSessions = C_CloseAllSessions;
	list->C_GetSessionInfo = C_GetSessionInfo;
	list->C_GetOperationState = C_GetOperationState;
	list->C_SetOperationState = C_SetOperationState;
	list->C_Login = C_Login;
	list->C_Logout = C_Logout;
	list->C_CreateObject = C_CreateObject;
	list->C_CopyObject = C_CopyObject;
	list->C_DestroyObject = C_DestroyObject;
	list->C_GetObjectSize = C_GetObjectSize;
	list->C_GetAttributeValue = C_GetAttributeValue;
	list->C_SetAttributeValue = C_SetAttributeValue;
	list->C_FindObjectsInit = C_FindObjectsInit;
	list->C_FindObjects = C_FindObjects;
	list->C_FindObjectsFinal = C_FindObjectsFinal;
	list->C_EncryptInit = C_EncryptInit;
	list->C_Encrypt = C_Encrypt;
	list->C_EncryptUpdate = C_EncryptUpdate;
	list->C_EncryptFinal = C_EncryptFinal;
	list->C_DecryptInit = C_DecryptInit;
	list->C_Decrypt = C_Decrypt;
	list->C_DecryptUpdate = C_DecryptUpdate;
	list->C_DecryptFinal = C_DecryptFinal;
	list->C_DigestInit = C_DigestInit;
	list->C_Digest = C_Digest;
	list->C_DigestUpdate = C_DigestUpdate;
	list->C_DigestKey = C_DigestKey;
	list->C_DigestFinal = C_DigestFinal;
	list->C_SignInit = C_SignInit;
	list->C_Sign = C_Sign;
	list->C_SignUpdate = C_SignUpdate;
	list->C_SignFinal = C_SignFinal;
	list->C_SignRecoverInit = C_SignRecoverInit;
	list->C_SignRecover = C_SignRecover;
	list->C_VerifyInit = C_VerifyInit;
	list->C_Verify = C_Verify;
	list->C_VerifyUpdate = C_VerifyUpdate;
	list->C_VerifyFinal = C_VerifyFinal;
	list->C_VerifyRecoverInit = C_VerifyRecoverInit;
	list->C_VerifyRecover = C_VerifyRecover;
	list->C_DigestEncryptUpdate = C_DigestEncryptUpdate;
	list->C_DecryptDigestUpdate = C_DecryptDigestUpdate;
	list->C_SignEncryptUpdate = C_SignEncryptUpdate;
	list->C_DecryptVerifyUpdate = C_DecryptVerifyUpdate;
	list->C_GenerateKey = C_GenerateKey;
	list->C_GenerateKeyPair = C_GenerateKeyPair;
	list->C_WrapKey = C_WrapKey;
	list->C_UnwrapKey = C_UnwrapKey;
	list->C_DeriveKey = C_DeriveKey;
	list->C_SeedRandom = C_SeedRandom;
	list->C_GenerateRandom = C_GenerateRandom;
	list->C_GetFunctionStatus = C_GetFunctionStatus;
	list->C_CancelFunction = C_CancelFunction;
	list->C_WaitForSlotEvent = C_WaitForSlotEvent;
	if (!v3) {
		return list;
	}

	/* Add also PKCS #11 3.0 functions if requested and fixup version */
	list_3_0 = (CK_FUNCTION_LIST_3_0_PTR) list;
	list_3_0->version.major = 3;
	list_3_0->version.minor = 0;
	list_3_0->C_GetInterfaceList = C_GetInterfaceList;
	list_3_0->C_GetInterface = C_GetInterface;
	list_3_0->C_LoginUser = C_LoginUser;
	list_3_0->C_SessionCancel = C_SessionCancel;
	list_3_0->C_MessageEncryptInit = C_MessageEncryptInit;
	list_3_0->C_EncryptMessage = C_EncryptMessage;
	list_3_0->C_EncryptMessageBegin = C_EncryptMessageBegin;
	list_3_0->C_EncryptMessageNext = C_EncryptMessageNext;
	list_3_0->C_MessageEncryptFinal = C_MessageEncryptFinal;
	list_3_0->C_MessageDecryptInit = C_MessageDecryptInit;
	list_3_0->C_DecryptMessage = C_DecryptMessage;
	list_3_0->C_DecryptMessageBegin = C_DecryptMessageBegin;
	list_3_0->C_DecryptMessageNext = C_DecryptMessageNext;
	list_3_0->C_MessageDecryptFinal = C_MessageDecryptFinal;
	list_3_0->C_MessageSignInit = C_MessageSignInit;
	list_3_0->C_SignMessage = C_SignMessage;
	list_3_0->C_SignMessageBegin = C_SignMessageBegin;
	list_3_0->C_SignMessageNext = C_SignMessageNext;
	list_3_0->C_MessageSignFinal = C_MessageSignFinal;
	list_3_0->C_MessageVerifyInit = C_MessageVerifyInit;
	list_3_0->C_VerifyMessage = C_VerifyMessage;
	list_3_0->C_VerifyMessageBegin = C_VerifyMessageBegin;
	list_3_0->C_VerifyMessageNext = C_VerifyMessageNext;
	list_3_0->C_MessageVerifyFinal = C_MessageVerifyFinal;

	return list_3_0;
}

/* The compatibility interfaces that can be returned from Interface functions
 * if the V3 API is used, but the proxied module does not support V3 API */
#define NUM_INTERFACES 1
CK_INTERFACE compat_interfaces[NUM_INTERFACES] = {
	{"PKCS 11", NULL, 0}
};

/* Inits the spy. If successful, po != NULL */
static CK_RV
init_spy(void)
{
	CK_FUNCTION_LIST_PTR po_v2 = NULL;
	const char *output, *module;
	CK_RV rv = CKR_OK;
#ifdef _WIN32
        char temp_path[PATH_MAX], expanded_path[PATH_MAX];
        DWORD temp_len, expanded_len;
        long rc;
        HKEY hKey;
#endif

	/* Allocates and initializes the pkcs11_spy structure */
	pkcs11_spy = allocate_function_list(0);
	if (pkcs11_spy == NULL) {
		return CKR_HOST_MEMORY;
	}
	pkcs11_spy_3_0 = allocate_function_list(1);
	if (pkcs11_spy_3_0 == NULL) {
		free(pkcs11_spy);
		return CKR_HOST_MEMORY;
	}

	compat_interfaces[0].pFunctionList = pkcs11_spy;

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
	modhandle = C_LoadModule(module, &po_v2);
	po = (CK_FUNCTION_LIST_3_0_PTR) po_v2;
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
spy_dump_mechanism_in(const char *name, CK_MECHANISM_PTR pMechanism)
{
	char param_name[64];

	if (!pMechanism) {
		fprintf(spy_output, "[in] %s = NULL\n", name);
		return;
	}

	fprintf(spy_output, "[in] %s->type = %s\n", name, lookup_enum(MEC_T, pMechanism->mechanism));
	switch (pMechanism->mechanism) {
	case CKM_AES_GCM:
		if (pMechanism->pParameter != NULL) {
			CK_GCM_PARAMS *param =
				(CK_GCM_PARAMS *) pMechanism->pParameter;
			snprintf(param_name, sizeof(param_name), "%s->pParameter->pIv[ulIvLen]", name);
			spy_dump_string_in(param_name,
				param->pIv, param->ulIvLen);
			snprintf(param_name, sizeof(param_name), "%s->pParameter->ulIvBits", name);
			spy_dump_ulong_in(param_name, param->ulIvBits);
			snprintf(param_name, sizeof(param_name), "%s->pParameter->pAAD[ulAADLen]", name);
			spy_dump_string_in(param_name,
				param->pAAD, param->ulAADLen);
			fprintf(spy_output, "[in] %s->pParameter->ulTagBits = %lu\n", name, param->ulTagBits);
		} else {
			fprintf(spy_output, "[in] %s->pParameter = NULL\n", name);
			break;
		}
		break;
	case CKM_ECDH1_DERIVE:
	case CKM_ECDH1_COFACTOR_DERIVE:
		if (pMechanism->pParameter != NULL) {
			CK_ECDH1_DERIVE_PARAMS *param =
				(CK_ECDH1_DERIVE_PARAMS *) pMechanism->pParameter;
			fprintf(spy_output, "[in] %s->pParameter->kdf = %s\n", name,
				lookup_enum(CKD_T, param->kdf));
			fprintf(spy_output, "[in] %s->pParameter->pSharedData[ulSharedDataLen] = ", name);
			print_generic(spy_output, 0, param->pSharedData,
				param->ulSharedDataLen, NULL);
			fprintf(spy_output, "[in] %s->pParameter->pPublicData[ulPublicDataLen] = ", name);
			print_generic(spy_output, 0, param->pPublicData,
				param->ulPublicDataLen, NULL);
		} else {
			fprintf(spy_output, "[in] %s->pParameter = NULL\n", name);
			break;
		}
		break;
	case CKM_ECMQV_DERIVE:
		if (pMechanism->pParameter != NULL) {
			CK_ECMQV_DERIVE_PARAMS *param =
				(CK_ECMQV_DERIVE_PARAMS *) pMechanism->pParameter;
			fprintf(spy_output, "[in] %s->pParameter->kdf = %s\n", name,
				lookup_enum(CKD_T, param->kdf));
			fprintf(spy_output, "%s->pParameter->pSharedData[ulSharedDataLen] = ", name);
			print_generic(spy_output, 0, param->pSharedData,
				param->ulSharedDataLen, NULL);
			fprintf(spy_output, "%s->pParameter->pPublicData[ulPublicDataLen] = ", name);
			print_generic(spy_output, 0, param->pPublicData,
				param->ulPublicDataLen, NULL);
			fprintf(spy_output, "%s->pParameter->ulPrivateDataLen = %lu", name,
				param->ulPrivateDataLen);
			fprintf(spy_output, "%s->pParameter->hPrivateData = %lu", name, param->hPrivateData);
			fprintf(spy_output, "%s->pParameter->pPublicData2[ulPublicDataLen2] = ", name);
			print_generic(spy_output, 0, param->pPublicData2,
				param->ulPublicDataLen2, NULL);
			fprintf(spy_output, "%s->pParameter->publicKey = %lu", name, param->publicKey);
		} else {
			fprintf(spy_output, "[in] %s->pParameter = NULL\n", name);
			break;
		}
		break;
	case CKM_RSA_PKCS_OAEP:
		if (pMechanism->pParameter != NULL) {
			CK_RSA_PKCS_OAEP_PARAMS *param =
				(CK_RSA_PKCS_OAEP_PARAMS *) pMechanism->pParameter;
			fprintf(spy_output, "[in] %s->pParameter->hashAlg = %s\n", name,
				lookup_enum(MEC_T, param->hashAlg));
			fprintf(spy_output, "[in] %s->pParameter->mgf = %s\n", name,
				lookup_enum(MGF_T, param->mgf));
			fprintf(spy_output, "[in] %s->pParameter->source = %lu\n", name, param->source);
			snprintf(param_name, sizeof(param_name), "%s->pParameter->pSourceData[ulSourceDalaLen]", name);
			spy_dump_string_in(param_name,
				param->pSourceData, param->ulSourceDataLen);
		} else {
			fprintf(spy_output, "[in] %s->pParameter = NULL\n", name);
			break;
		}
		break;
	case CKM_RSA_PKCS_PSS:
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
	case CKM_SHA384_RSA_PKCS_PSS:
	case CKM_SHA512_RSA_PKCS_PSS:
		if (pMechanism->pParameter != NULL) {
			CK_RSA_PKCS_PSS_PARAMS *param =
				(CK_RSA_PKCS_PSS_PARAMS *) pMechanism->pParameter;
			fprintf(spy_output, "[in] %s->pParameter->hashAlg = %s\n", name,
				lookup_enum(MEC_T, param->hashAlg));
			fprintf(spy_output, "[in] %s->pParameter->mgf = %s\n", name,
				lookup_enum(MGF_T, param->mgf));
			fprintf(spy_output, "[in] %s->pParameter->sLen = %lu\n", name,
				param->sLen);
		} else {
			fprintf(spy_output, "[in] %s->pParameter = NULL\n", name);
			break;
		}
		break;
	default:
		snprintf(param_name, sizeof(param_name), "%s->pParameter[ulParameterLen]", name);
		spy_dump_string_in(param_name, pMechanism->pParameter, pMechanism->ulParameterLen);
		break;
	}
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
	if (ppFunctionList == NULL)
		return retne(CKR_ARGUMENTS_BAD);
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
		fprintf(spy_output, "[in] type = %30s\n", name);
	else
		fprintf(spy_output, "[in] type = Unknown Mechanism (%08lx)\n", type);

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
	fprintf(spy_output, "[in] pApplication = %p\n", pApplication);
	fprintf(spy_output, "[in] Notify = %p\n", (void *)Notify);
	rv = po->C_OpenSession(slotID, flags, pApplication, Notify, phSession);
	if (phSession)
		spy_dump_ulong_out("*phSession", *phSession);
	else
		fprintf(spy_output, "[out] phSession = %p\n", phSession);
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
	spy_dump_mechanism_in("pMechanism", pMechanism);
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
	spy_dump_mechanism_in("pMechanism", pMechanism);
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
	spy_dump_mechanism_in("pMechanism", pMechanism);
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
	spy_dump_mechanism_in("pMechanism", pMechanism);
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
	spy_dump_mechanism_in("pMechanism", pMechanism);
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
	spy_dump_mechanism_in("pMechanism", pMechanism);
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
	spy_dump_mechanism_in("pMechanism", pMechanism);
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
	spy_dump_mechanism_in("pMechanism", pMechanism);
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
	spy_dump_mechanism_in("pMechanism", pMechanism);
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
	spy_dump_mechanism_in("pMechanism", pMechanism);
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
	spy_dump_mechanism_in("pMechanism", pMechanism);
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
	spy_dump_mechanism_in("pMechanism", pMechanism);
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
	if (pSlot != NULL) {
		spy_dump_ulong_in("pSlot", *pSlot);
	}
	rv = po->C_WaitForSlotEvent(flags, pSlot, pRserved);
	return retne(rv);
}

/* PKCS #11 3.0 functions */
static void
spy_interface_function_list(CK_INTERFACE_PTR pInterface)
{
	CK_VERSION *version;

	/* Do not touch unknown interfaces. We can not do anything with these */
	if (strcmp(pInterface->pInterfaceName, "PKCS 11") != 0) {
		return;
	}

	version = (CK_VERSION *)pInterface->pFunctionList;
	if (version->major == 2) {
		pInterface->pFunctionList = pkcs11_spy;
	} else if (version->major == 3 && version->minor == 0) {
		pInterface->pFunctionList = pkcs11_spy_3_0;
	}
}

CK_RV
C_GetInterfaceList(CK_INTERFACE_PTR pInterfacesList, CK_ULONG_PTR pulCount)
{
	CK_RV rv;

	if (po == NULL) {
		CK_RV rv = init_spy();
		if (rv != CKR_OK)
			return rv;
	}

	enter("C_GetInterfaceList");
	if (po->version.major < 3) {
		fprintf(spy_output, "[compat]\n");

		memcpy(pInterfacesList, compat_interfaces, NUM_INTERFACES * sizeof(CK_INTERFACE));
		*pulCount = NUM_INTERFACES;

		spy_dump_desc_out("pInterfacesList");
		print_interfaces_list(spy_output, pInterfacesList, *pulCount);
		spy_dump_ulong_out("*pulCount", *pulCount);
		return retne(CKR_OK);
	}
	rv = po->C_GetInterfaceList(pInterfacesList, pulCount);
	if (rv == CKR_OK) {
		spy_dump_desc_out("pInterfacesList");
		print_interfaces_list(spy_output, pInterfacesList, *pulCount);
		spy_dump_ulong_out("*pulCount", *pulCount);

		/* Now, replace function lists of known interfaces (PKCS 11, v 2.x and 3.0) */
		if (pInterfacesList != NULL) {
			unsigned long i;
			for (i = 0; i < *pulCount; i++) {
				spy_interface_function_list(&pInterfacesList[i]);
			}
		}
	}
	return retne(rv);
}

CK_RV
C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
	CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags)
{
	CK_RV rv;

	if (po == NULL) {
		CK_RV rv = init_spy();
		if (rv != CKR_OK)
			return rv;
	}

	enter("C_GetInterface");
	if (po->version.major < 3) {
		fprintf(spy_output, "[compat]\n");
	}
	spy_dump_string_in("pInterfaceName", pInterfaceName, strlen((char *)pInterfaceName));
	if (pVersion != NULL) {
		fprintf(spy_output, "[in] pVersion = %d.%d\n", pVersion->major, pVersion->minor);
	} else {
		fprintf(spy_output, "[in] pVersion = NULL\n");
	}
	fprintf(spy_output, "[in] flags = %s\n",
		(flags & CKF_INTERFACE_FORK_SAFE ? "CKF_INTERFACE_FORK_SAFE" : ""));
	if (po->version.major >= 3) {
		rv = po->C_GetInterface(pInterfaceName, pVersion, ppInterface, flags);
		if (ppInterface != NULL) {
			spy_interface_function_list(*ppInterface);
		}
	} else {
		if ((pInterfaceName == NULL_PTR || strcmp((char *)pInterfaceName, "PKCS 11") == 0) &&
			(pVersion == NULL_PTR || (pVersion->major == 2 && pVersion->minor == 11)) &&
			flags == 0) {
			*ppInterface = &compat_interfaces[0];
			return retne(CKR_OK);
		}
		/* We can not serve this particular interface */
		return retne(CKR_ARGUMENTS_BAD);
	}

	return retne(rv);
}

CK_RV
C_LoginUser(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
	CK_CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pUsername, CK_ULONG ulUsernameLen)
{
	CK_RV rv;

	enter("C_LoginUser");
	spy_dump_ulong_in("hSession", hSession);
	fprintf(spy_output, "[in] userType = %s\n",
			lookup_enum(USR_T, userType));
	spy_dump_string_in("pPin[ulPinLen]", pPin, ulPinLen);
	spy_dump_string_in("pUsername[ulUsernameLen]", pUsername, ulUsernameLen);
	rv = po->C_LoginUser(hSession, userType, pPin, ulPinLen, pUsername, ulUsernameLen);

	return retne(rv);
}

CK_RV C_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags)
{
	CK_RV rv;

	enter("C_SessionCancel");
	spy_dump_ulong_in("hSession", hSession);
	fprintf(spy_output, "[in] flags = %s%s%s%s%s%s%s%s%s%s%s%s\n",
		(flags & CKF_ENCRYPT)           ? "Encrypt "  : "",
		(flags & CKF_DECRYPT)           ? "Decrypt "  : "",
		(flags & CKF_DIGEST)            ? "Digest "   : "",
		(flags & CKF_SIGN)              ? "Sign "     : "",
		(flags & CKF_SIGN_RECOVER)      ? "SigRecov " : "",
		(flags & CKF_VERIFY)            ? "Verify "   : "",
		(flags & CKF_VERIFY_RECOVER)    ? "VerRecov " : "",
		(flags & CKF_GENERATE)          ? "Generate " : "",
		(flags & CKF_GENERATE_KEY_PAIR) ? "KeyPair "  : "",
		(flags & CKF_WRAP)              ? "Wrap "     : "",
		(flags & CKF_UNWRAP)            ? "Unwrap "   : "",
		(flags & CKF_DERIVE)            ? "Derive "   : "");
	rv = po->C_SessionCancel(hSession, flags);

	return retne(rv);
}

CK_RV
C_MessageEncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	enter("C_MessageEncryptInit");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_mechanism_in("pMechanism", pMechanism);
	spy_dump_ulong_in("hKey", hKey);
	rv = po->C_MessageEncryptInit(hSession, pMechanism, hKey);
	return retne(rv);
}

CK_RV
C_EncryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen,
	CK_BYTE_PTR pPlaintext, CK_ULONG ulPlaintextLen,
	CK_BYTE_PTR pCiphertext, CK_ULONG_PTR pulCiphertextLen)
{
	CK_RV rv;

	enter("C_EncryptMessage");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pParameter[ulParameterLen]", pParameter, ulParameterLen);
	spy_dump_string_in("pAssociatedData[ulAssociatedDataLen]", pAssociatedData, ulAssociatedDataLen);
	spy_dump_string_in("pPlaintext[ulPlaintextLen]", pPlaintext, ulPlaintextLen);
	rv = po->C_EncryptMessage(hSession, pParameter, ulParameterLen,
		pAssociatedData, ulAssociatedDataLen, pPlaintext, ulPlaintextLen,
		pCiphertext, pulCiphertextLen);
	if (rv == CKR_OK) {
		spy_dump_string_out("pCiphertext[*pulCiphertextLen]", pCiphertext, *pulCiphertextLen);
	}
	return retne(rv);
}

CK_RV
C_EncryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
{
	CK_RV rv;

	enter("C_EncryptMessageBegin");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pParameter[ulParameterLen]", pParameter, ulParameterLen);
	spy_dump_string_in("pAssociatedData[ulAssociatedDataLen]", pAssociatedData, ulAssociatedDataLen);
	rv = po->C_EncryptMessageBegin(hSession, pParameter, ulParameterLen,
		pAssociatedData, ulAssociatedDataLen);
	return retne(rv);
}

CK_RV
C_EncryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pPlaintextPart, CK_ULONG ulPlaintextPartLen,
	CK_BYTE_PTR pCiphertextPart, CK_ULONG_PTR pulCiphertextPartLen, CK_FLAGS flags)
{
	CK_RV rv;

	enter("C_EncryptMessageNext");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pParameter[ulParameterLen]", pParameter, ulParameterLen);
	spy_dump_string_in("pPlaintextPart[ulPlaintextPartLen]", pPlaintextPart, ulPlaintextPartLen);
	rv = po->C_EncryptMessageNext(hSession, pParameter, ulParameterLen,
		pPlaintextPart, ulPlaintextPartLen, pCiphertextPart, pulCiphertextPartLen, flags);
	if (rv == CKR_OK) {
		spy_dump_string_out("pCiphertextPart[*pulCiphertextPartLen]",
			pCiphertextPart, *pulCiphertextPartLen);
	}
	fprintf(spy_output, "[in] flags = %s\n",
		(flags & CKF_END_OF_MESSAGE ? "CKF_END_OF_MESSAGE" : ""));
	return retne(rv);
}

CK_RV
C_MessageEncryptFinal(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;

	enter("C_MessageEncryptFinal");
	spy_dump_ulong_in("hSession", hSession);
	rv = po->C_MessageEncryptFinal(hSession);
	return retne(rv);
}

CK_RV
C_MessageDecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	enter("C_MessageDecryptInit");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_mechanism_in("pMechanism", pMechanism);
	spy_dump_ulong_in("hKey", hKey);
	rv = po->C_MessageDecryptInit(hSession, pMechanism, hKey);
	return retne(rv);
}

CK_RV
C_DecryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen,
	CK_BYTE_PTR pCiphertext, CK_ULONG ulCiphertextLen,
	CK_BYTE_PTR pPlaintext, CK_ULONG_PTR pulPlaintextLen)
{
	CK_RV rv;

	enter("C_DecryptMessage");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pParameter[ulParameterLen]", pParameter, ulParameterLen);
	spy_dump_string_in("pAssociatedData[ulAssociatedDataLen]", pAssociatedData, ulAssociatedDataLen);
	spy_dump_string_in("pCiphertext[ulCiphertextLen]", pCiphertext, ulCiphertextLen);
	rv = po->C_DecryptMessage(hSession, pParameter, ulParameterLen,
		pAssociatedData, ulAssociatedDataLen, pCiphertext, ulCiphertextLen,
		pPlaintext, pulPlaintextLen);
	if (rv == CKR_OK) {
		spy_dump_string_out("pPlaintext[*pulPlaintextLen]", pPlaintext, *pulPlaintextLen);
	}
	return retne(rv);
}

CK_RV
C_DecryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pAssociatedData, CK_ULONG ulAssociatedDataLen)
{
	CK_RV rv;

	enter("C_DecryptMessageBegin");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pParameter[ulParameterLen]", pParameter, ulParameterLen);
	spy_dump_string_in("pAssociatedData[ulAssociatedDataLen]", pAssociatedData, ulAssociatedDataLen);
	rv = po->C_DecryptMessageBegin(hSession, pParameter, ulParameterLen,
		pAssociatedData, ulAssociatedDataLen);
	return retne(rv);
}

CK_RV
C_DecryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pCiphertextPart, CK_ULONG ulCiphertextPartLen,
	CK_BYTE_PTR pPlaintextPart, CK_ULONG_PTR pulPlaintextPartLen, CK_FLAGS flags)
{
	CK_RV rv;

	enter("C_DecryptMessageNext");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pParameter[ulParameterLen]", pParameter, ulParameterLen);
	spy_dump_string_in("pCiphertextPart[ulCiphertextPartLen]", pCiphertextPart, ulCiphertextPartLen);
	rv = po->C_DecryptMessageNext(hSession, pParameter, ulParameterLen,
		pCiphertextPart, ulCiphertextPartLen, pPlaintextPart, pulPlaintextPartLen, flags);
	if (rv == CKR_OK) {
		spy_dump_string_out("pPlaintextPart[*pulPlaintextPartLen]",
			pPlaintextPart, *pulPlaintextPartLen);
	}
	fprintf(spy_output, "[in] flags = %s\n",
		(flags & CKF_END_OF_MESSAGE ? "CKF_END_OF_MESSAGE" : ""));
	return retne(rv);
}

CK_RV
C_MessageDecryptFinal(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;

	enter("C_MessageDecryptFinal");
	spy_dump_ulong_in("hSession", hSession);
	rv = po->C_MessageDecryptFinal(hSession);
	return retne(rv);
}

CK_RV
C_MessageSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;

	enter("C_MessageSignInit");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_mechanism_in("pMechanism", pMechanism);
	spy_dump_ulong_in("hKey", hKey);
	rv = po->C_MessageSignInit(hSession, pMechanism, hKey);
	return retne(rv);
}

CK_RV
C_SignMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;

	enter("C_SignMessage");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pParameter[ulParameterLen]", pParameter, ulParameterLen);
	spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
	rv = po->C_SignMessage(hSession, pParameter, ulParameterLen,
		pData, ulDataLen, pSignature, pulSignatureLen);
	if (rv == CKR_OK) {
		spy_dump_string_out("pSignature[*pulSignatureLen]", pSignature, *pulSignatureLen);
	}
	return retne(rv);
}

CK_RV
C_SignMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
{
	CK_RV rv;

	enter("C_SignMessageBegin");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pParameter[ulParameterLen]", pParameter, ulParameterLen);
	rv = po->C_SignMessageBegin(hSession, pParameter, ulParameterLen);
	return retne(rv);
}

CK_RV
C_SignMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;

	enter("C_SignMessageNext");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pParameter[ulParameterLen]", pParameter, ulParameterLen);
	spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
	rv = po->C_SignMessageNext(hSession, pParameter, ulParameterLen,
		pData, ulDataLen, pSignature, pulSignatureLen);
	if (rv == CKR_OK) {
		spy_dump_string_out("pSignature[*pulSignatureLen]", pSignature, *pulSignatureLen);
	}
	return retne(rv);
}

CK_RV
C_MessageSignFinal(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;

	enter("C_MessageSignFinal");
	spy_dump_ulong_in("hSession", hSession);
	rv = po->C_MessageSignFinal(hSession);
	return retne(rv);
}

CK_RV
C_MessageVerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE  hKey)
{
	CK_RV rv;

	enter("C_MessageVerifyInit");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_mechanism_in("pMechanism", pMechanism);
	spy_dump_ulong_in("hKey", hKey);
	rv = po->C_MessageVerifyInit(hSession, pMechanism, hKey);
	return retne(rv);
}

CK_RV
C_VerifyMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_RV rv;

	enter("C_VerifyMessage");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pParameter[ulParameterLen]", pParameter, ulParameterLen);
	spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
	spy_dump_string_in("pSignature[ulSignatureLen]", pSignature, ulSignatureLen);
	rv = po->C_VerifyMessage(hSession, pParameter, ulParameterLen,
		pData, ulDataLen, pSignature, ulSignatureLen);
	return retne(rv);
}

CK_RV
C_VerifyMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen)
{
	CK_RV rv;

	enter("C_VerifyMessageBegin");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pParameter[ulParameterLen]", pParameter, ulParameterLen);
	rv = po->C_VerifyMessageBegin(hSession, pParameter, ulParameterLen);
	return retne(rv);
}

CK_RV C_VerifyMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter, CK_ULONG ulParameterLen,
	CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_RV rv;

	enter("C_VerifyMessageNext");
	spy_dump_ulong_in("hSession", hSession);
	spy_dump_string_in("pParameter[ulParameterLen]", pParameter, ulParameterLen);
	spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
	spy_dump_string_in("pSignature[ulSignatureLen]", pSignature, ulSignatureLen);
	rv = po->C_VerifyMessageNext(hSession, pParameter, ulParameterLen,
		pData, ulDataLen, pSignature, ulSignatureLen);
	return retne(rv);
}

CK_RV C_MessageVerifyFinal(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;

	enter("C_MessageVerifyFinal");
	spy_dump_ulong_in("hSession", hSession);
	rv = po->C_MessageVerifyFinal(hSession);
	return retne(rv);
}
