/*
 * Copyright (C) 2003 Mathias Brossard <mathias.brossard@idealx.com>
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

#include <stdlib.h>
#include <stdio.h>

#ifndef WIN32
#include <dlfcn.h>
#else
#include <Windows.h>
#endif

#include "pkcs11_display.h"

#define __PASTE(x,y)      x##y

/*  Declare all spy_* Cryptoki function */

#define CK_NEED_ARG_LIST  1
#define CK_PKCS11_FUNCTION_INFO(name) \
CK_RV __PASTE(spy_,name)

#include "pkcs11f.h"

CK_FUNCTION_LIST_PTR pkcs11_spy = NULL;
CK_FUNCTION_LIST_PTR po = NULL;
FILE *spy_output = NULL;

#ifndef WIN32
#define DEFAULT_PKCSLIB "/usr/local/lib/pkcs11/opensc-pkcs11.so"
#else
#define DEFAULT_DLL "opensc-pkcs11"
#endif

CK_FUNCTION_LIST  *pkcs11_get_spy_function_list( void )
{
  CK_FUNCTION_LIST  *funcs;
  CK_RV            rc;
  CK_RV  (*pfoo)();
#ifndef WIN32
  void    *d;
  char    *e;
  char    *z = DEFAULT_PKCSLIB;

  e = getenv("PKCS11SPY");
  if ( e == NULL) {
    e = z;
  }
  d = dlopen(e, RTLD_NOW);
  if ( d == NULL ) {
    return FALSE;
  }

  pfoo = (CK_RV (*)())dlsym(d,"C_GetFunctionList");
#else
  HINSTANCE libHandle = NULL;
  char    *z = DEFAULT_DLL;

  libHandle = LoadLibrary(z);
  if(libHandle) {
    return FALSE;
  }
  pfoo = (CK_RV (*)())GetProcAddress(libHandle, "C_GetFunctionList");
#endif

  if (pfoo == NULL ) {
    return FALSE;
  }
  rc = pfoo(&funcs);

  if (rc != CKR_OK) {
    funcs = NULL;
  }

  return funcs;
}

#undef CK_NEED_ARG_LIST
#undef CK_PKCS11_FUNCTION_INFO
#define CK_PKCS11_FUNCTION_INFO(name) \
    pkcs11_spy->name = &__PASTE(spy_,name);

int init_spy()
{
  char *file;
  pkcs11_spy = (CK_FUNCTION_LIST_PTR) 
    malloc(sizeof(CK_FUNCTION_LIST));
  if(pkcs11_spy) {
#include "pkcs11f.h"
  }
  file = getenv("PKCS11SPY_OUTPUT");
  if(file) {
    spy_output = fopen(file, "a");
  } else {
    spy_output = stderr;
  }
  po = pkcs11_get_spy_function_list();
  return 0;
}

CK_RV C_GetFunctionList
(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
  init_spy();
  if(pkcs11_spy) {
    *ppFunctionList = pkcs11_spy;
    return CKR_OK;
  }
  return CKR_HOST_MEMORY;
}

void enter(char *function) 
{
  static int count = 0;
  fprintf(spy_output, "\n\n%d: %s\n", count++, function);
}

CK_RV retne(CK_RV rv) 
{
  fprintf(spy_output, "Returned:  %ld %s\n", rv,
	  lookup_enum ( RV_T, rv ));
  return rv;
}

#define ENTER() enter(__FUNCTION__ + 4)
#define RETURN() return retne(rv)

void spy_dump_string_in(char *name, CK_VOID_PTR data, CK_ULONG size) 
{
  fprintf(spy_output, "[in] %s ", name);
  print_generic(spy_output, 0, data, size, NULL);
}

void spy_dump_string_out(char *name, CK_VOID_PTR data, CK_ULONG size) 
{
  fprintf(spy_output, "[out] %s ", name);
  print_generic(spy_output, 0, data, size, NULL);
}

void spy_dump_ulong_in(char *name, CK_ULONG value) 
{
  fprintf(spy_output, "[in] %s = 0x%lx\n", name, value);
}

void spy_dump_ulong_out(char *name, CK_ULONG value) 
{
  fprintf(spy_output, "[out] %s = 0x%lx\n", name, value);
}

void spy_dump_desc_out(char *name) 
{
  fprintf(spy_output, "[out] %s: \n", name);
}

void spy_dump_array_out(char *name, CK_ULONG size) 
{
  fprintf(spy_output, "[out] %s[%ld]: \n", name, size);
}

void spy_attribute_req_in(char *name, CK_ATTRIBUTE_PTR pTemplate,
			  CK_ULONG  ulCount) 
{
  fprintf(spy_output, "[in] %s[%ld]: \n", name, ulCount);
  print_attribute_list_req(spy_output, pTemplate, ulCount);
}

void spy_attribute_list_in(char *name, CK_ATTRIBUTE_PTR pTemplate,
			  CK_ULONG  ulCount) 
{
  fprintf(spy_output, "[in] %s[%ld]: \n", name, ulCount);
  print_attribute_list(spy_output, pTemplate, ulCount);
}

void spy_attribute_list_out(char *name, CK_ATTRIBUTE_PTR pTemplate,
			  CK_ULONG  ulCount) 
{
  fprintf(spy_output, "[out] %s[%ld]: \n", name, ulCount);
  print_attribute_list(spy_output, pTemplate, ulCount);
}

CK_RV spy_C_Initialize(CK_VOID_PTR pInitArgs)
{
  CK_RV rv;
  ENTER();
  rv = po->C_Initialize(pInitArgs);
  RETURN();
}

CK_RV spy_C_Finalize(CK_VOID_PTR pReserved)
{
  CK_RV rv;
  ENTER();
  rv = po->C_Finalize(pReserved);
  RETURN();
}

CK_RV spy_C_GetInfo(CK_INFO_PTR pInfo)
{
  CK_RV rv;
  ENTER();
  rv = po->C_GetInfo(pInfo);
  if(rv == CKR_OK) {
    print_ck_info(spy_output, pInfo);
  }
  RETURN();
}

CK_RV spy_C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
  CK_RV rv;
  ENTER();
  rv = po->C_GetFunctionList(ppFunctionList);
  RETURN();
}


CK_RV spy_C_GetSlotList(CK_BBOOL tokenPresent,
			CK_SLOT_ID_PTR pSlotList, 
			CK_ULONG_PTR pulCount)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("tokenPresent", tokenPresent);
  rv = po->C_GetSlotList(tokenPresent, pSlotList, pulCount);
  if(rv == CKR_OK) {
    spy_dump_desc_out("pSlotList");
    print_slot_list(spy_output, pSlotList, *pulCount);
    spy_dump_ulong_out("*pulCount", *pulCount);
  }
  RETURN();
}

CK_RV spy_C_GetSlotInfo(CK_SLOT_ID slotID,
			CK_SLOT_INFO_PTR pInfo)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("slotID", slotID);
  rv = po->C_GetSlotInfo(slotID, pInfo);
  if(rv == CKR_OK) {
    spy_dump_desc_out("pInfo");
    print_slot_info(spy_output, pInfo);
  }
  RETURN();
}

CK_RV spy_C_GetTokenInfo(CK_SLOT_ID slotID, 
			 CK_TOKEN_INFO_PTR pInfo)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("slotID", slotID);
  rv = po->C_GetTokenInfo(slotID, pInfo);
  if(rv == CKR_OK) {
    spy_dump_desc_out("pInfo");
    print_token_info(spy_output, pInfo);
  }
  RETURN();
}

CK_RV spy_C_GetMechanismList(CK_SLOT_ID  slotID, 
			     CK_MECHANISM_TYPE_PTR pMechanismList,
			     CK_ULONG_PTR  pulCount)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("slotID", slotID);
  rv = po->C_GetMechanismList(slotID, pMechanismList, pulCount);
  if(rv == CKR_OK) {
    spy_dump_array_out("pMechanismList", *pulCount);
    print_mech_list(spy_output, pMechanismList, *pulCount);
  }
  RETURN();
}

CK_RV spy_C_GetMechanismInfo(CK_SLOT_ID  slotID, 
			     CK_MECHANISM_TYPE type,
			     CK_MECHANISM_INFO_PTR pInfo)
{
  CK_RV rv;
  const char *name = lookup_enum(MEC_T, type);
  ENTER();
  spy_dump_ulong_in("slotID", slotID);
  if (name) {
    fprintf(spy_output, "%30s \n", name);
  } else {
    fprintf(spy_output, " Unknown Mechanism (%08lx)  \n", type);
  }
  rv = po->C_GetMechanismInfo(slotID, type, pInfo);
  if(rv == CKR_OK) {
    spy_dump_desc_out("pInfo");
    print_mech_info(spy_output, type, pInfo);
  }
  RETURN();
}

CK_RV spy_C_InitToken (CK_SLOT_ID slotID, 
		       CK_UTF8CHAR_PTR pPin, 
		       CK_ULONG ulPinLen, 
		       CK_UTF8CHAR_PTR pLabel)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("slotID", slotID);
  spy_dump_string_in("pPin[ulPinLen]", pPin, ulPinLen);
  spy_dump_string_in("pLabel[32]", pLabel, 32);
  rv = po->C_InitToken (slotID, pPin, ulPinLen, pLabel);
  RETURN();
}

CK_RV spy_C_InitPIN(CK_SESSION_HANDLE hSession,
		    CK_UTF8CHAR_PTR pPin, 
		    CK_ULONG  ulPinLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pPin[ulPinLen]", pPin, ulPinLen);
  rv = po->C_InitPIN(hSession, pPin, ulPinLen);
  RETURN();
}

CK_RV spy_C_SetPIN(CK_SESSION_HANDLE hSession, 
		   CK_UTF8CHAR_PTR pOldPin, 
		   CK_ULONG  ulOldLen, 
		   CK_UTF8CHAR_PTR pNewPin, 
		   CK_ULONG  ulNewLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pOldPin[ulOldLen]", pOldPin, ulOldLen);
  spy_dump_string_in("pNewPin[ulNewLen]", pNewPin, ulNewLen);
  rv = po->C_SetPIN(hSession, pOldPin, ulOldLen, 
		    pNewPin, ulNewLen);
  RETURN();
}

CK_RV spy_C_OpenSession(CK_SLOT_ID  slotID, 
			CK_FLAGS  flags,  
			CK_VOID_PTR  pApplication, 
			CK_NOTIFY  Notify, 
			CK_SESSION_HANDLE_PTR phSession)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("slotID", slotID);
  spy_dump_ulong_in("flags", flags);
  fprintf(spy_output, "pApplication=%p\n", pApplication);
  fprintf(spy_output, "Notify=%p\n", (void *)Notify);
  rv = po->C_OpenSession(slotID, flags, pApplication,
			 Notify, phSession);
  spy_dump_ulong_out("*phSession", *phSession);
  RETURN();
}


CK_RV spy_C_CloseSession(CK_SESSION_HANDLE hSession)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_CloseSession(hSession);
  RETURN();
}


CK_RV spy_C_CloseAllSessions(CK_SLOT_ID slotID)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("slotID", slotID);
  rv = po->C_CloseAllSessions(slotID);
  RETURN();
}


CK_RV spy_C_GetSessionInfo(CK_SESSION_HANDLE hSession, 
			   CK_SESSION_INFO_PTR pInfo)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_GetSessionInfo(hSession, pInfo);
  if(rv == CKR_OK) {
    spy_dump_desc_out("pInfo");
    print_session_info(spy_output, pInfo);
  }
  RETURN();
}


CK_RV spy_C_GetOperationState(CK_SESSION_HANDLE hSession,  
			      CK_BYTE_PTR pOperationState, 
			      CK_ULONG_PTR pulOperationStateLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_GetOperationState(hSession, pOperationState,
			       pulOperationStateLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pOperationState[*pulOperationStateLen]", pOperationState, *pulOperationStateLen);
  }
  RETURN();
}


CK_RV spy_C_SetOperationState(CK_SESSION_HANDLE hSession,  
			      CK_BYTE_PTR pOperationState, 
			      CK_ULONG  ulOperationStateLen, 
			      CK_OBJECT_HANDLE hEncryptionKey, 
			      CK_OBJECT_HANDLE hAuthenticationKey)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pOperationState[ulOperationStateLen]", pOperationState, ulOperationStateLen);
  spy_dump_ulong_in("hEncryptionKey", hEncryptionKey);
  spy_dump_ulong_in("hAuthenticationKey", hAuthenticationKey);
  rv = po->C_SetOperationState(hSession, pOperationState,
			       ulOperationStateLen,
			       hEncryptionKey,
			       hAuthenticationKey);
  RETURN();
}


CK_RV spy_C_Login(CK_SESSION_HANDLE hSession, 
		  CK_USER_TYPE userType, 
		  CK_UTF8CHAR_PTR pPin, 
		  CK_ULONG  ulPinLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  fprintf(spy_output, "[in] userType = %s\n", lookup_enum(USR_T, userType));
  spy_dump_string_in("pPin[ulPinLen]", pPin, ulPinLen);
  rv = po->C_Login(hSession, userType, pPin, ulPinLen);
  RETURN();
}

CK_RV spy_C_Logout(CK_SESSION_HANDLE hSession)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_Logout(hSession);
  RETURN();
}

CK_RV spy_C_CreateObject(CK_SESSION_HANDLE hSession, 
			 CK_ATTRIBUTE_PTR pTemplate, 
			 CK_ULONG  ulCount, 
			 CK_OBJECT_HANDLE_PTR phObject)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_attribute_list_in("pTemplate", pTemplate, ulCount);
  rv = po->C_CreateObject(hSession, pTemplate, ulCount, phObject);
  if (rv == CKR_OK) {
    spy_dump_ulong_out("*phObject", *phObject);
  }
  RETURN();
}

CK_RV spy_C_CopyObject(CK_SESSION_HANDLE hSession, 
		       CK_OBJECT_HANDLE hObject, 
		       CK_ATTRIBUTE_PTR pTemplate, 
		       CK_ULONG  ulCount, 
		       CK_OBJECT_HANDLE_PTR phNewObject)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_ulong_in("hObject", hObject);
  spy_attribute_list_in("pTemplate", pTemplate, ulCount);
  rv = po->C_CopyObject(hSession, hObject, pTemplate, ulCount, phNewObject);
  if (rv == CKR_OK) {
    spy_dump_ulong_out("*phNewObject", *phNewObject);
  }
  RETURN();
}


CK_RV spy_C_DestroyObject(CK_SESSION_HANDLE hSession, 
			  CK_OBJECT_HANDLE hObject)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_ulong_in("hObject", hObject);
  rv = po->C_DestroyObject(hSession, hObject);
  RETURN();
}


CK_RV spy_C_GetObjectSize(CK_SESSION_HANDLE hSession, 
			  CK_OBJECT_HANDLE hObject, 
			  CK_ULONG_PTR pulSize)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_ulong_in("hObject", hObject);
  rv = po->C_GetObjectSize(hSession, hObject, pulSize);
  if (rv == CKR_OK) {
    spy_dump_ulong_out("*pulSize", *pulSize);
  }
  RETURN();
}


CK_RV spy_C_GetAttributeValue(CK_SESSION_HANDLE hSession, 
			      CK_OBJECT_HANDLE hObject, 
			      CK_ATTRIBUTE_PTR pTemplate, 
			      CK_ULONG  ulCount)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_attribute_req_in("pTemplate", pTemplate, ulCount);
  rv = po->C_GetAttributeValue(hSession, hObject, pTemplate, ulCount);
  if (rv == CKR_OK) {
    spy_attribute_list_out("pTemplate", pTemplate, ulCount);
  }
  RETURN();
}


CK_RV spy_C_SetAttributeValue(CK_SESSION_HANDLE hSession, 
			      CK_OBJECT_HANDLE hObject, 
			      CK_ATTRIBUTE_PTR pTemplate, 
			      CK_ULONG  ulCount)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_ulong_in("hObject", hObject);
  spy_attribute_list_in("pTemplate", pTemplate, ulCount);
  rv = po->C_SetAttributeValue(hSession, hObject, pTemplate, ulCount);
  RETURN();
}


CK_RV spy_C_FindObjectsInit(CK_SESSION_HANDLE hSession, 
			    CK_ATTRIBUTE_PTR pTemplate, 
			    CK_ULONG  ulCount)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_attribute_list_in("pTemplate", pTemplate, ulCount);
  rv = po->C_FindObjectsInit(hSession, pTemplate, ulCount);
  RETURN();
}


CK_RV spy_C_FindObjects(CK_SESSION_HANDLE hSession,  
			CK_OBJECT_HANDLE_PTR phObject,  
			CK_ULONG  ulMaxObjectCount, 
			CK_ULONG_PTR  pulObjectCount)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_ulong_in("ulMaxObjectCount", ulMaxObjectCount);
  rv = po->C_FindObjects(hSession, phObject, ulMaxObjectCount,
			 pulObjectCount);
  if (rv == CKR_OK) {
    CK_ULONG          i;
    spy_dump_ulong_out("ulObjectCount", *pulObjectCount);
    for (i = 0; i < *pulObjectCount; i++) {
      fprintf(spy_output, "Object %ld Matches\n", phObject[i]);
    }
  }
  RETURN();
}


CK_RV spy_C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_FindObjectsFinal(hSession);
  RETURN();
}

CK_RV spy_C_EncryptInit(CK_SESSION_HANDLE hSession, 
			CK_MECHANISM_PTR pMechanism, 
			CK_OBJECT_HANDLE hKey)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
  spy_dump_ulong_in("hKey", hKey);
  rv = po->C_EncryptInit(hSession, pMechanism, hKey);
  RETURN();
}


CK_RV spy_C_Encrypt(CK_SESSION_HANDLE hSession,  
		    CK_BYTE_PTR pData,  
		    CK_ULONG  ulDataLen,  
		    CK_BYTE_PTR pEncryptedData, 
		    CK_ULONG_PTR pulEncryptedDataLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
  rv = po->C_Encrypt(hSession, pData, ulDataLen,
		     pEncryptedData, pulEncryptedDataLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pEncryptedData[*pulEncryptedDataLen]",
			pEncryptedData, *pulEncryptedDataLen);
  }
  RETURN();
}


CK_RV spy_C_EncryptUpdate(CK_SESSION_HANDLE hSession,  
			  CK_BYTE_PTR pPart,  
			  CK_ULONG  ulPartLen,  
			  CK_BYTE_PTR pEncryptedPart, 
			  CK_ULONG_PTR pulEncryptedPartLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
  rv = po->C_EncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart,
			   pulEncryptedPartLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pEncryptedPart[*pulEncryptedPartLen]",
			pEncryptedPart, *pulEncryptedPartLen);
  }
  RETURN();
}

CK_RV spy_C_EncryptFinal(CK_SESSION_HANDLE hSession,  
			 CK_BYTE_PTR pLastEncryptedPart, 
			 CK_ULONG_PTR pulLastEncryptedPartLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_EncryptFinal(hSession, pLastEncryptedPart,
			  pulLastEncryptedPartLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pLastEncryptedPart[*pulLastEncryptedPartLen]",
			pLastEncryptedPart, *pulLastEncryptedPartLen);
  }
  RETURN();
}


CK_RV spy_C_DecryptInit(CK_SESSION_HANDLE hSession, 
			CK_MECHANISM_PTR pMechanism, 
			CK_OBJECT_HANDLE hKey)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
  spy_dump_ulong_in("hKey", hKey);
  rv = po->C_DecryptInit(hSession, pMechanism, hKey);
  RETURN();
}


CK_RV spy_C_Decrypt(CK_SESSION_HANDLE hSession,  
		    CK_BYTE_PTR pEncryptedData, 
		    CK_ULONG  ulEncryptedDataLen, 
		    CK_BYTE_PTR pData,  
		    CK_ULONG_PTR pulDataLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pEncryptedData[ulEncryptedDataLen]",
		      pEncryptedData, ulEncryptedDataLen);
  rv = po->C_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, 
		     pData, pulDataLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pData[*pulDataLen]", pData, *pulDataLen);
  }
  RETURN();
}


CK_RV spy_C_DecryptUpdate(CK_SESSION_HANDLE hSession,  
			  CK_BYTE_PTR pEncryptedPart, 
			  CK_ULONG  ulEncryptedPartLen, 
			  CK_BYTE_PTR pPart,  
			  CK_ULONG_PTR pulPartLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pEncryptedPart[ulEncryptedPartLen]",
		      pEncryptedPart, ulEncryptedPartLen);
  rv = po->C_DecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen,
			   pPart, pulPartLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pPart[*pulPartLen]", pPart, *pulPartLen);
  }
  RETURN();
}


CK_RV spy_C_DecryptFinal(CK_SESSION_HANDLE hSession, 
			 CK_BYTE_PTR pLastPart, 
			 CK_ULONG_PTR pulLastPartLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_DecryptFinal(hSession, pLastPart, pulLastPartLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pLastPart[*pulLastPartLen]",
			pLastPart, *pulLastPartLen);
  }
  RETURN();
}

CK_RV spy_C_DigestInit(CK_SESSION_HANDLE hSession, 
		       CK_MECHANISM_PTR pMechanism)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
  rv = po->C_DigestInit(hSession, pMechanism);
  RETURN();
}


CK_RV spy_C_Digest(CK_SESSION_HANDLE hSession, 
		   CK_BYTE_PTR pData, 
		   CK_ULONG  ulDataLen, 
		   CK_BYTE_PTR pDigest, 
		   CK_ULONG_PTR pulDigestLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
  rv = po->C_Digest(hSession, pData, ulDataLen, pDigest, pulDigestLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pDigest[*pulDigestLen]",
			pDigest, *pulDigestLen);
  }
  RETURN();
}


CK_RV spy_C_DigestUpdate(CK_SESSION_HANDLE hSession, 
			 CK_BYTE_PTR pPart, 
			 CK_ULONG  ulPartLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
  rv = po->C_DigestUpdate(hSession, pPart, ulPartLen);
  RETURN();
}


CK_RV spy_C_DigestKey(CK_SESSION_HANDLE hSession, 
		      CK_OBJECT_HANDLE hKey)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_ulong_in("hKey", hKey);
  rv = po->C_DigestKey(hSession, hKey);
  RETURN();
}


CK_RV spy_C_DigestFinal(CK_SESSION_HANDLE hSession, 
			CK_BYTE_PTR pDigest, 
			CK_ULONG_PTR pulDigestLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_DigestFinal(hSession, pDigest, pulDigestLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pDigest[*pulDigestLen]",
			pDigest, *pulDigestLen);
  }
  RETURN();
}

CK_RV spy_C_SignInit(CK_SESSION_HANDLE hSession, 
		     CK_MECHANISM_PTR pMechanism, 
		     CK_OBJECT_HANDLE hKey)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
  spy_dump_ulong_in("hKey", hKey);
  rv = po->C_SignInit(hSession, pMechanism, hKey);
  RETURN();
}


CK_RV spy_C_Sign(CK_SESSION_HANDLE hSession, 
		 CK_BYTE_PTR pData,  
		 CK_ULONG  ulDataLen, 
		 CK_BYTE_PTR pSignature, 
		 CK_ULONG_PTR pulSignatureLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
  rv = po->C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pSignature[*pulSignatureLen]",
			pSignature, *pulSignatureLen);
  }
  RETURN();
}


CK_RV spy_C_SignUpdate(CK_SESSION_HANDLE hSession, 
		       CK_BYTE_PTR pPart, 
		       CK_ULONG  ulPartLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
  rv = po->C_SignUpdate(hSession, pPart, ulPartLen);
  RETURN();
}


CK_RV spy_C_SignFinal(CK_SESSION_HANDLE hSession, 
		      CK_BYTE_PTR pSignature, 
		      CK_ULONG_PTR pulSignatureLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_SignFinal(hSession, pSignature, pulSignatureLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pSignature[*pulSignatureLen]",
			pSignature, *pulSignatureLen);
  }
  RETURN();
}


CK_RV spy_C_SignRecoverInit(CK_SESSION_HANDLE hSession, 
			    CK_MECHANISM_PTR pMechanism, 
			    CK_OBJECT_HANDLE hKey)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
  spy_dump_ulong_in("hKey", hKey);
  rv = po->C_SignRecoverInit(hSession, pMechanism, hKey);
  RETURN();
}


CK_RV spy_C_SignRecover(CK_SESSION_HANDLE hSession, 
			CK_BYTE_PTR pData,  
			CK_ULONG  ulDataLen, 
			CK_BYTE_PTR pSignature, 
			CK_ULONG_PTR pulSignatureLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
  rv = po->C_SignRecover(hSession, pData, ulDataLen, 
			 pSignature, pulSignatureLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pSignature[*pulSignatureLen]",
			pSignature, *pulSignatureLen);
  }
  RETURN();
}

CK_RV spy_C_VerifyInit(CK_SESSION_HANDLE hSession, 
		       CK_MECHANISM_PTR pMechanism, 
		       CK_OBJECT_HANDLE hKey)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
  spy_dump_ulong_in("hKey", hKey);
  rv = po->C_VerifyInit(hSession, pMechanism, hKey);
  RETURN();
}


CK_RV spy_C_Verify(CK_SESSION_HANDLE hSession, 
		   CK_BYTE_PTR pData,  
		   CK_ULONG  ulDataLen, 
		   CK_BYTE_PTR pSignature, 
		   CK_ULONG  ulSignatureLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pData[ulDataLen]", pData, ulDataLen);
  spy_dump_string_in("pSignature[ulSignatureLen]",
		     pSignature, ulSignatureLen);
  rv = po->C_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
  RETURN();
}


CK_RV spy_C_VerifyUpdate(CK_SESSION_HANDLE hSession, 
			 CK_BYTE_PTR pPart, 
			 CK_ULONG  ulPartLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
  rv = po->C_VerifyUpdate(hSession, pPart, ulPartLen);
  RETURN();
}


CK_RV spy_C_VerifyFinal(CK_SESSION_HANDLE hSession, 
			CK_BYTE_PTR pSignature, 
			CK_ULONG  ulSignatureLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pSignature[ulSignatureLen]",
		     pSignature, ulSignatureLen);
  rv = po->C_VerifyFinal(hSession, pSignature, ulSignatureLen);
  RETURN();
}


CK_RV spy_C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, 
			      CK_MECHANISM_PTR pMechanism, 
			      CK_OBJECT_HANDLE hKey)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
  spy_dump_ulong_in("hKey", hKey);
  rv = po->C_VerifyRecoverInit(hSession, pMechanism, hKey);
  RETURN();
}


CK_RV spy_C_VerifyRecover(CK_SESSION_HANDLE hSession, 
			  CK_BYTE_PTR pSignature, 
			  CK_ULONG  ulSignatureLen, 
			  CK_BYTE_PTR pData,  
			  CK_ULONG_PTR pulDataLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pSignature[ulSignatureLen]",
		     pSignature, ulSignatureLen);
  rv = po->C_VerifyRecover(hSession, pSignature, ulSignatureLen,
			   pData, pulDataLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pData[*pulDataLen]", pData, *pulDataLen);
  }
  RETURN();
}

CK_RV spy_C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,  
				CK_BYTE_PTR pPart,  
				CK_ULONG  ulPartLen,  
				CK_BYTE_PTR pEncryptedPart, 
				CK_ULONG_PTR pulEncryptedPartLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
  rv = po->C_DigestEncryptUpdate(hSession, pPart, ulPartLen,  
				 pEncryptedPart, pulEncryptedPartLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pEncryptedPart[*pulEncryptedPartLen]",
			pEncryptedPart, *pulEncryptedPartLen);
  }
  RETURN();
}


CK_RV spy_C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,  
				CK_BYTE_PTR pEncryptedPart, 
				CK_ULONG  ulEncryptedPartLen, 
				CK_BYTE_PTR pPart,  
				CK_ULONG_PTR pulPartLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pEncryptedPart[ulEncryptedPartLen]",
		      pEncryptedPart, ulEncryptedPartLen);
  rv = po->C_DecryptDigestUpdate(hSession, pEncryptedPart,
				 ulEncryptedPartLen,
				 pPart,  pulPartLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pPart[*pulPartLen]", pPart, *pulPartLen);
  }
  RETURN();
}


CK_RV spy_C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,  
			      CK_BYTE_PTR pPart,  
			      CK_ULONG  ulPartLen,  
			      CK_BYTE_PTR pEncryptedPart, 
			      CK_ULONG_PTR pulEncryptedPartLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pPart[ulPartLen]", pPart, ulPartLen);
  rv = po->C_SignEncryptUpdate(hSession, pPart, ulPartLen,
			       pEncryptedPart, pulEncryptedPartLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pEncryptedPart[*pulEncryptedPartLen]",
			pEncryptedPart, *pulEncryptedPartLen);
  }
  RETURN();
}


CK_RV spy_C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,  
				CK_BYTE_PTR pEncryptedPart, 
				CK_ULONG  ulEncryptedPartLen, 
				CK_BYTE_PTR pPart,  
				CK_ULONG_PTR pulPartLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pEncryptedPart[ulEncryptedPartLen]",
		      pEncryptedPart, ulEncryptedPartLen);
  rv = po->C_DecryptVerifyUpdate(hSession, pEncryptedPart,
				 ulEncryptedPartLen, pPart,  
				 pulPartLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pPart[*pulPartLen]", pPart, *pulPartLen);
  }
  RETURN();
}

CK_RV spy_C_GenerateKey(CK_SESSION_HANDLE hSession, 
			CK_MECHANISM_PTR pMechanism, 
			CK_ATTRIBUTE_PTR pTemplate, 
			CK_ULONG  ulCount, 
			CK_OBJECT_HANDLE_PTR phKey)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
  spy_attribute_list_in("pTemplate", pTemplate, ulCount);
  rv = po->C_GenerateKey(hSession, pMechanism, pTemplate, 
			 ulCount, phKey);
  if (rv == CKR_OK) {
    spy_dump_ulong_out("hKey", *phKey);
  }
  RETURN();
}

CK_RV spy_C_GenerateKeyPair(CK_SESSION_HANDLE hSession,   
			    CK_MECHANISM_PTR pMechanism,   
			    CK_ATTRIBUTE_PTR pPublicKeyTemplate,  
			    CK_ULONG  ulPublicKeyAttributeCount, 
			    CK_ATTRIBUTE_PTR pPrivateKeyTemplate,  
			    CK_ULONG  ulPrivateKeyAttributeCount, 
			    CK_OBJECT_HANDLE_PTR phPublicKey,   
			    CK_OBJECT_HANDLE_PTR phPrivateKey)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
  spy_attribute_list_in("pPublicKeyTemplate", pPublicKeyTemplate, ulPublicKeyAttributeCount);
  spy_attribute_list_in("pPrivateKeyTemplate", pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
  rv = po->C_GenerateKeyPair(hSession, pMechanism, pPublicKeyTemplate,  
			     ulPublicKeyAttributeCount, pPrivateKeyTemplate,  
			     ulPrivateKeyAttributeCount, phPublicKey,   
			     phPrivateKey);
  if (rv == CKR_OK) {
    spy_dump_ulong_out("hPublicKey", *phPublicKey);
    spy_dump_ulong_out("hPrivateKey", *phPrivateKey);
  }
  RETURN();
}


CK_RV spy_C_WrapKey(CK_SESSION_HANDLE hSession, 
		    CK_MECHANISM_PTR pMechanism, 
		    CK_OBJECT_HANDLE hWrappingKey, 
		    CK_OBJECT_HANDLE hKey,  
		    CK_BYTE_PTR pWrappedKey, 
		    CK_ULONG_PTR pulWrappedKeyLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
  spy_dump_ulong_in("hWrappingKey", hWrappingKey);
  spy_dump_ulong_in("hKey", hKey);
  rv = po->C_WrapKey(hSession, pMechanism, hWrappingKey, 
		     hKey, pWrappedKey, pulWrappedKeyLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("pWrappedKey[*pulWrappedKeyLen]",
			pWrappedKey, *pulWrappedKeyLen);
  }
  RETURN();
}

CK_RV spy_C_UnwrapKey(CK_SESSION_HANDLE hSession,  
		      CK_MECHANISM_PTR pMechanism, 
		      CK_OBJECT_HANDLE hUnwrappingKey, 
		      CK_BYTE_PTR  pWrappedKey, 
		      CK_ULONG  ulWrappedKeyLen, 
		      CK_ATTRIBUTE_PTR pTemplate,  
		      CK_ULONG  ulAttributeCount, 
		      CK_OBJECT_HANDLE_PTR phKey)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
  spy_dump_ulong_in("hUnwrappingKey", hUnwrappingKey);
  spy_dump_string_in("pWrappedKey[ulWrappedKeyLen]",
		      pWrappedKey, ulWrappedKeyLen);
  spy_attribute_list_in("pTemplate", pTemplate, ulAttributeCount);
  rv = po->C_UnwrapKey(hSession, pMechanism, hUnwrappingKey, 
		       pWrappedKey, ulWrappedKeyLen, pTemplate,  
		       ulAttributeCount, phKey);
  if (rv == CKR_OK) {
    spy_dump_ulong_out("hKey", *phKey);
  }
  RETURN();
}

CK_RV spy_C_DeriveKey(CK_SESSION_HANDLE hSession,  
		      CK_MECHANISM_PTR pMechanism, 
		      CK_OBJECT_HANDLE hBaseKey,  
		      CK_ATTRIBUTE_PTR pTemplate,  
		      CK_ULONG  ulAttributeCount, 
		      CK_OBJECT_HANDLE_PTR phKey)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  fprintf(spy_output, "pMechanism->type=%s\n", lookup_enum(MEC_T, pMechanism->mechanism));
  spy_dump_ulong_in("hBaseKey", hBaseKey);
  spy_attribute_list_in("pTemplate", pTemplate, ulAttributeCount);
  rv = po->C_DeriveKey(hSession, pMechanism, hBaseKey,  
		       pTemplate, ulAttributeCount, phKey);
  if (rv == CKR_OK) {
    spy_dump_ulong_out("hKey", *phKey);
  }
  RETURN();
}

CK_RV spy_C_SeedRandom(CK_SESSION_HANDLE hSession, 
		       CK_BYTE_PTR pSeed, 
		       CK_ULONG  ulSeedLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  spy_dump_string_in("pSeed[ulSeedLen]", pSeed, ulSeedLen);
  rv = po->C_SeedRandom(hSession, pSeed, ulSeedLen);
  RETURN();
}


CK_RV spy_C_GenerateRandom(CK_SESSION_HANDLE hSession, 
			   CK_BYTE_PTR RandomData, 
			   CK_ULONG  ulRandomLen)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_GenerateRandom(hSession, RandomData, ulRandomLen);
  if (rv == CKR_OK) {
    spy_dump_string_out("RandomData[ulRandomLen]",
			RandomData, ulRandomLen);
  }
  RETURN();
}


CK_RV spy_C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_GetFunctionStatus(hSession);
  RETURN();
}

CK_RV spy_C_CancelFunction(CK_SESSION_HANDLE hSession)
{
  CK_RV rv;
  ENTER();
  spy_dump_ulong_in("hSession", hSession);
  rv = po->C_CancelFunction(hSession);
  RETURN();
}

CK_RV spy_C_WaitForSlotEvent(CK_FLAGS flags, 
			     CK_SLOT_ID_PTR pSlot, 
			     CK_VOID_PTR pRserved)
{
  CK_RV rv;
  ENTER();
  rv = po->C_WaitForSlotEvent(flags, pSlot, pRserved);
  RETURN();
}
