#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <winscard.h>

#include "sc-pkcs11.h"
#include "../sc.h"

struct sc_context *ctx = NULL;
struct sc_pkcs15_card *p15card = NULL;

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

	ctx = NULL;
	rv = sc_establish_context(&ctx);
	if (rv != 0) {
		LOG("ERROR: Unable to connect to Resource Manager\n");
		return CKR_DEVICE_ERROR;
	}
        return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
        int i;

	LOG("C_Finalize(0x%x)\n", pReserved);

	if (p15card != NULL) {
		sc_disconnect_card(p15card->card);
		sc_pkcs15_destroy(p15card);
	}
	sc_destroy_context(ctx);

        return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	LOG("C_GetInfo(0x%x)\n", pInfo);
        memset(pInfo, 0, sizeof(CK_INFO));
	pInfo->cryptokiVersion.major = 2;
	pInfo->cryptokiVersion.minor = 10;
	strcpy(pInfo->manufacturerID, "Timo Teras & Juha Yrjola");
	strcpy(pInfo->libraryDescription, "PC/SC PKCS#15 SmartCard reader");
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
		*pulCount = ctx->reader_count;
                return CKR_OK;
	}

	num = ctx->reader_count > *pulCount ? *pulCount : ctx->reader_count;
	for (i = 0; i < num; i++)
		pSlotList[i] = i;
        *pulCount = num;

	return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	LOG("C_GetSlotInfo(%d, 0x%x)\n", slotID, pInfo);

	if (slotID < 0 || slotID >= ctx->reader_count)
                return CKR_SLOT_ID_INVALID;

	memset(pInfo, 0, sizeof(CK_SLOT_INFO));
	strncpy(pInfo->slotDescription, ctx->readers[slotID],
		sizeof(pInfo->slotDescription));
	strcpy(pInfo->manufacturerID, "PC/SC interface");
	pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
	if (sc_detect_card(ctx, slotID) == 1)
		pInfo->flags |= CKF_TOKEN_PRESENT;
	else {
		if (p15card != NULL) {
			sc_disconnect_card(p15card->card);
			sc_pkcs15_destroy(p15card);
			p15card = NULL;
		}
	}
	pInfo->hardwareVersion.major = 1;
	pInfo->firmwareVersion.major = 1;

	return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	int r;
	struct sc_card *card;
	
        LOG("C_GetTokenInfo(%d, 0x%x)\n", slotID, pInfo);
	if (slotID < 0 || slotID >= ctx->reader_count)
                return CKR_SLOT_ID_INVALID;

	memset(pInfo, 0, sizeof(CK_SLOT_INFO));

	if (p15card == NULL) {
		r = sc_connect_card(ctx, slotID, &card);
		if (r)
			return CKR_DEVICE_ERROR;
		r = sc_pkcs15_init(card, &p15card);
		if (r) {
			/* PKCS#15 compatible SC probably not present */
			sc_disconnect_card(card);
			return CKR_DEVICE_ERROR;
		}
	}
	strcpy(pInfo->label, p15card->label);
	strcpy(pInfo->manufacturerID, "unknown");
	strcpy(pInfo->model, "unknown");
	strcpy(pInfo->serialNumber, "unknown");
	pInfo->flags = CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED;
	pInfo->ulMaxSessionCount = 1;	/* opened in exclusive mode */
	pInfo->ulSessionCount = 0;
	pInfo->ulMaxRwSessionCount = 1;
	pInfo->ulRwSessionCount = 0;
	pInfo->ulMaxPinLen = 8;	/* FIXME: get these from PIN objects */
	pInfo->ulMinPinLen = 4;
	pInfo->ulTotalPublicMemory = 0;
	pInfo->ulFreePublicMemory = 0;
	pInfo->ulTotalPrivateMemory = 0;
	pInfo->ulFreePrivateMemory = 0;
	pInfo->hardwareVersion.major = 1;
	pInfo->hardwareVersion.minor = 0;
	pInfo->firmwareVersion.major = 1;
	pInfo->firmwareVersion.minor = 0;
	
        return CKR_OK;
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
