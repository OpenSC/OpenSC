#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <winscard.h>

#include "sc-pkcs11.h"

SCARDCONTEXT sc_ctx;
int sc_num_readers;
char *sc_reader_name[16];

void LOG(char *format, ...)
{
	va_list valist;
	FILE *out;

	out = fopen("/tmp/libsc-pkcs11.log", "a");
	if (out != NULL) {
                va_start(valist, format);
		vfprintf(out, format, valist);
                va_end(valist);
		fclose(out);
	}
}

CK_RV C_Initialize(CK_VOID_PTR pReserved)
{
	int reader_count, reader_buf_size, rv;
        char *reader_buf, *p;

	LOG("C_Initialize(0x%x)\n", pReserved);

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &sc_ctx);
	if (rv != SCARD_S_SUCCESS) {
		LOG("ERROR: Unable to connect to Resource Manager\n");
		return CKR_DEVICE_ERROR;
	}

        // Fetch the list of readers
	SCardListReaders(sc_ctx, NULL, NULL, (LPDWORD) &reader_buf_size);
	reader_buf = (char*) malloc(reader_buf_size);
	SCardListReaders(sc_ctx, NULL, reader_buf, (LPDWORD) &reader_buf_size);
	p = reader_buf;
	sc_num_readers = reader_count = 0;
	do {
		sc_reader_name[sc_num_readers++] = strdup(p);
		while (*p++ != 0);
		p++;
	} while (p < reader_buf + reader_buf_size);
        free(reader_buf);

        return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
        int i;

	LOG("C_Finalize(0x%x)\n", pReserved);

	for (i = 0; i < sc_num_readers; i++)
		free(sc_reader_name[i]);

	SCardReleaseContext(sc_ctx);

        return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	LOG("C_GetInfo(0x%x)\n", pInfo);
        memset(pInfo, 0, sizeof(CK_INFO));
	pInfo->cryptokiVersion.major = 2;
	pInfo->cryptokiVersion.minor = 10;
	strcpy(pInfo->manufacturerID, "Timo Teras & Juha Yrjola");
	strcpy(pInfo->libraryDescription, "PCSC PKCS#15 SmartCard reader");
	pInfo->libraryVersion.major = 0;
	pInfo->libraryVersion.minor = 1;
        return CKR_OK;
}

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
        LOG("C_GetFunctionList(0x%x)\n", ppFunctionList);
	*ppFunctionList = &function_list;
	return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL       tokenPresent,  /* only slots with token present */
		    CK_SLOT_ID_PTR pSlotList,     /* receives the array of slot IDs */
		    CK_ULONG_PTR   pulCount)      /* receives the number of slots */
{
        int i, num;

        LOG("C_GetSlotList(%d, 0x%x, 0x%x)\n", tokenPresent, pSlotList, pulCount);

	if (pSlotList == NULL_PTR) {
		*pulCount = sc_num_readers;
                return CKR_OK;
	}

	num = sc_num_readers > *pulCount ? *pulCount : sc_num_readers;
	for (i = 0; i < num; i++)
		pSlotList[i] = i;
        *pulCount = num;

	return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	LOG("C_GetSlotInfo(%d, 0x%x)\n", slotID, pInfo);

	if (slotID < 0 || slotID >= sc_num_readers)
                return CKR_SLOT_ID_INVALID;

	memset(pInfo, 0, sizeof(CK_SLOT_INFO));
	strncpy(pInfo->slotDescription, sc_reader_name[slotID],
		sizeof(pInfo->slotDescription));
	strcpy(pInfo->manufacturerID, "PCSC interface");
	pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
	pInfo->hardwareVersion.major = 1;
	pInfo->firmwareVersion.major = 1;

	return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
        LOG("C_GetTokenInfo(%d, 0x%x)\n", slotID, pInfo);
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE_PTR pMechanismList,
                         CK_ULONG_PTR pulCount)
{
        LOG("C_GetMechanismList(%d, 0x%x, 0x%x)\n", slotID, pMechanismList, pulCount);
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE type,
			 CK_MECHANISM_INFO_PTR pInfo)
{
        LOG("C_GetMechanismInfo(%d, %d, 0x%x)\n", slotID, type, pInfo);
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitToken(CK_SLOT_ID slotID,
		  CK_CHAR_PTR pPin,
		  CK_ULONG ulPinLen,
		  CK_CHAR_PTR pLabel)
{
        LOG("C_InitToken(%d, '%s', %d, '%s')\n", slotID, pPin, ulPinLen, pLabel);
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession,
		CK_CHAR_PTR pPin,
		CK_ULONG ulPinLen)
{
        LOG("C_InitPIN(%d, '%s', %d)\n", hSession, pPin, ulPinLen);
        return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession,
	       CK_CHAR_PTR pOldPin,
	       CK_ULONG ulOldLen,
	       CK_CHAR_PTR pNewPin,
	       CK_ULONG ulNewLen)
{
        LOG("C_SetPIN(%d, '%s', %d, '%s', %d)\n", hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
        return CKR_FUNCTION_NOT_SUPPORTED;
}



