/*
 * generic.c: Generic PKCS#11 functions for slot and token management
 *
 * Copyright (C) 2001  Timo Teräs <timo.teras@iki.fi>
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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include "sc-pkcs11.h"

struct sc_context *ctx = NULL;
struct pkcs11_slot slot[PKCS11_MAX_SLOTS];
struct pkcs11_session *session[PKCS11_MAX_SESSIONS+1];

void LOG(char *format, ...)
{
#if 1
	va_list valist;
	FILE *out;

	out = fopen("/tmp/libopensc-pkcs11.log", "a");
	if (out != NULL) {
                va_start(valist, format);
		vfprintf(out, format, valist);
                va_end(valist);
		fclose(out);
	}
#endif
}

void hex_dump(const unsigned char *buf, int count)
{
	int i;
	for (i = 0; i < count; i++) {
                unsigned char c = buf[i];
		int printch = 0;
		if (!isalnum(c) && !ispunct(c) && !isspace(c))
			printch = 0;
                if (printch)
			LOG("%02X%c ", c, c);
		else
                        LOG("%02X  ", c);
	}
	LOG("\n");
}

CK_RV C_Initialize(CK_VOID_PTR pReserved)
{
	int rv;

	LOG("C_Initialize(0x%x)\n", pReserved);

	memset(session, 0, sizeof(session));
        memset(slot, 0, sizeof(slot));

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

	for (i=0; i < PKCS11_MAX_SLOTS; i++)
		slot_disconnect(i);

	sc_destroy_context(ctx);
        return CKR_OK;
}

void strcpy_bp(char *dst, const char *src, int dstsize)
{
	int c = strlen(src) > dstsize ? dstsize : strlen(src);
	
	memcpy(dst, src, c);
	dstsize -= c;
	memset(dst + c, ' ', dstsize);
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	LOG("C_GetInfo(0x%x)\n", pInfo);
        memset(pInfo, 0, sizeof(CK_INFO));
	pInfo->cryptokiVersion.major = 2;
	pInfo->cryptokiVersion.minor = 11;
	strcpy_bp((char *) pInfo->manufacturerID, "OpenSC Project",
		  sizeof(pInfo->manufacturerID));
	strcpy_bp((char *) pInfo->libraryDescription, "PKCS#15 SmartCard reader",
		  sizeof(pInfo->libraryDescription));
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
        int i;

        LOG("C_GetSlotList(%d, 0x%x, 0x%x)\n", tokenPresent, pSlotList, pulCount);

	if (pSlotList == NULL_PTR) {
		*pulCount = ctx->reader_count;
                return CKR_OK;
	}

	if (*pulCount < ctx->reader_count) {
		*pulCount = ctx->reader_count;
                return CKR_BUFFER_TOO_SMALL;
	}

	for (i = 0; i < ctx->reader_count; i++)
		pSlotList[i] = i;
        *pulCount = ctx->reader_count;

	return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	LOG("C_GetSlotInfo(%d, 0x%x)\n", slotID, pInfo);

	if (slotID < 0 || slotID >= ctx->reader_count)
                return CKR_SLOT_ID_INVALID;

	strcpy_bp((char *) pInfo->slotDescription, ctx->readers[slotID],
		sizeof(pInfo->slotDescription));
	strcpy_bp((char *) pInfo->manufacturerID, "PC/SC interface",
		sizeof(pInfo->manufacturerID));
	pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
	if (sc_detect_card(ctx, slotID) == 1) {
                LOG("Detected card in slot %d\n", slotID);
		pInfo->flags |= CKF_TOKEN_PRESENT;
	} else {
		LOG("No card in slot %d\n", slotID);
                slot_disconnect(slotID);
	}
	pInfo->hardwareVersion.major = 1;
	pInfo->hardwareVersion.minor = 1;
	pInfo->firmwareVersion.major = 1;
	pInfo->firmwareVersion.minor = 1;
	
	LOG("C_GetSlotInfo() ret: flags %X\n", pInfo->flags);

	return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	int r;

        LOG("C_GetTokenInfo(%d, 0x%x)\n", slotID, pInfo);
	if (slotID < 0 || slotID >= ctx->reader_count)
                return CKR_SLOT_ID_INVALID;

	memset(pInfo, 0, sizeof(CK_SLOT_INFO));

	if (!(slot[slotID].flags & SLOT_CONNECTED)) {
		r = slot_connect(slotID);
                if (r)
			return r;
	}
	strcpy_bp((char *) pInfo->label, slot[slotID].p15card->label, 32);
	strcpy_bp((char *) pInfo->manufacturerID, slot[slotID].p15card->manufacturer_id, 32);
	strcpy_bp((char *) pInfo->model, "PKCS#15 SC", sizeof(pInfo->model));
	strcpy_bp((char *) pInfo->serialNumber, slot[slotID].p15card->serial_number, 16);

	pInfo->flags = CKF_RNG | CKF_USER_PIN_INITIALIZED | CKF_LOGIN_REQUIRED;
	pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulSessionCount = 0; /* FIXME */
	pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulRwSessionCount = 0; /* FIXME */

	if (slot[slotID].p15card->pin_info[0].magic == SC_PKCS15_PIN_MAGIC) {
		pInfo->ulMaxPinLen = slot[slotID].p15card->pin_info[0].stored_length;
		pInfo->ulMinPinLen = slot[slotID].p15card->pin_info[0].min_length;
	} else {
		/* choose reasonable defaults */
		pInfo->ulMaxPinLen = 8;
		pInfo->ulMinPinLen = 4;
	}
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
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
	static const CK_MECHANISM_TYPE mechanism_list[] = {
		CKM_RSA_PKCS,
		CKM_RSA_X_509,
		CKM_SHA1_RSA_PKCS,
	};
        const int numMechanisms = sizeof(mechanism_list) / sizeof(mechanism_list[0]);

	LOG("C_GetMechanismList(%d, 0x%x, 0x%x)\n", slotID, pMechanismList, pulCount);
	if (slotID < 0 || slotID >= ctx->reader_count)
                return CKR_SLOT_ID_INVALID;

	if (pMechanismList == NULL_PTR) {
		*pulCount = numMechanisms;
                return CKR_OK;
	}

	if (*pulCount < numMechanisms) {
		*pulCount = numMechanisms;
                return CKR_BUFFER_TOO_SMALL;
	}
        memcpy(pMechanismList, &mechanism_list, sizeof(mechanism_list));

        return CKR_OK;
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
