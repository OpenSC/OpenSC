/*
 * pkcs11-global.c: PKCS#11 module level functions and function table
 *
 * Copyright (C) 2002  Timo Teräs <timo.teras@iki.fi>
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

#include "sc-pkcs11.h"

#include <sc-log.h>

struct sc_context *context = NULL;
struct sc_pkcs11_pool session_pool;
struct sc_pkcs11_slot virtual_slots[SC_PKCS11_MAX_VIRTUAL_SLOTS];
struct sc_pkcs11_card card_table[SC_PKCS11_MAX_READERS];

CK_FUNCTION_LIST pkcs11_function_list;

CK_RV C_Initialize(CK_VOID_PTR pReserved)
{
	int i, rc;

	if (context != NULL) {
		error(context, "C_Initialize(): Cryptoki already initialized\n");
                return CKR_CRYPTOKI_ALREADY_INITIALIZED;
	}
	rc = sc_establish_context(&context);
	if (rc != 0)
		return CKR_DEVICE_ERROR;
        context->use_std_output = 1;

        pool_initialize(&session_pool);
	for (i=0; i<SC_PKCS11_MAX_VIRTUAL_SLOTS; i++)
                slot_initialize(i, &virtual_slots[i]);
	for (i=0; i<SC_PKCS11_MAX_READERS; i++)
                card_initialize(i);

	debug(context, "Cryptoki initialized\n");
	return CKR_OK;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	int i;

	debug(context, "Shutting down Cryptoki\n");
	for (i=0; i<context->reader_count; i++)
                card_removed(i);

	sc_destroy_context(context);
        return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	debug(context, "Cryptoki info query\n");

	memset(pInfo, 0, sizeof(CK_INFO));
	pInfo->cryptokiVersion.major = 2;
	pInfo->cryptokiVersion.minor = 11;
	strcpy_bp(pInfo->manufacturerID,
		  "OpenSC Project (www.opensc.org)",
		  sizeof(pInfo->manufacturerID));
	strcpy_bp(pInfo->libraryDescription,
		  "SmartCard PKCS#11 API",
		  sizeof(pInfo->libraryDescription));
	pInfo->libraryVersion.major = 0;
	pInfo->libraryVersion.minor = 2;

        return CKR_OK;
}	

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	*ppFunctionList = &pkcs11_function_list;
	return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL       tokenPresent,  /* only slots with token present */
		    CK_SLOT_ID_PTR pSlotList,     /* receives the array of slot IDs */
		    CK_ULONG_PTR   pulCount)      /* receives the number of slots */
{
	int numMatches, i;

	if (context == NULL_PTR)
	    return CKR_CRYPTOKI_NOT_INITIALIZED;

	debug(context, "Getting slot listing\n");

	for (i=0; i<context->reader_count; i++)
		card_detect(i);

	if (tokenPresent) {
		numMatches = 0;
		for (i=0; i<SC_PKCS11_MAX_VIRTUAL_SLOTS; i++)
			if (virtual_slots[i].slot_info.flags & CKF_TOKEN_PRESENT)
                                numMatches++;
	} else {
                numMatches = SC_PKCS11_MAX_VIRTUAL_SLOTS;
	}

	if (pSlotList == NULL_PTR) {
		debug(context, "was only a size inquiry (%d)\n", numMatches);
		*pulCount = numMatches;
                return CKR_OK;
	}

	if (*pulCount < numMatches) {
		debug(context, "buffer was too small (needed %d)\n", numMatches);
		*pulCount = numMatches;
                return CKR_BUFFER_TOO_SMALL;
	}

        numMatches = 0;
	for (i=0; i<SC_PKCS11_MAX_VIRTUAL_SLOTS; i++)
		if ((!tokenPresent) || (virtual_slots[i].slot_info.flags & CKF_TOKEN_PRESENT))
                        pSlotList[numMatches++] = i;

	*pulCount = numMatches;

	debug(context, "returned %d slots\n", numMatches);
        return CKR_OK;

#if 0
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
#endif
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	struct sc_pkcs11_slot *slot;
        CK_RV rv;

	rv = slot_get_slot(slotID, &slot);
	if (rv != CKR_OK)
		return rv;

	debug(context, "Getting info about slot %d\n", slotID);
	memcpy(pInfo, &slot->slot_info, sizeof(CK_SLOT_INFO));
        return CKR_OK;

#if 0
	LOG("C_GetSlotInfo(%d, 0x%x)\n", slotID, pInfo);

	if (slotID < 0 || slotID >= ctx->reader_count)
                return CKR_SLOT_ID_INVALID;

	strcpy_bp(pInfo->slotDescription, ctx->readers[slotID],
		sizeof(pInfo->slotDescription));
	strcpy_bp(pInfo->manufacturerID, "PC/SC interface",
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
#endif
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	struct sc_pkcs11_slot *slot;
        CK_RV rv;

	rv = slot_get_token(slotID, &slot);
	if (rv != CKR_OK)
		return rv;

	debug(context, "Getting info about token in slot %d\n", slotID);
	memcpy(pInfo, &slot->token_info, sizeof(CK_TOKEN_INFO));
        return CKR_OK;

#if 0
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
	strcpy_bp(pInfo->label, slot[slotID].p15card->label, 32);
	strcpy_bp(pInfo->manufacturerID, slot[slotID].p15card->manufacturer_id, 32);
	strcpy_bp(pInfo->model, "PKCS#15 SC", sizeof(pInfo->model));
	strcpy_bp(pInfo->serialNumber, slot[slotID].p15card->serial_number, 16);

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
#endif
        return CKR_OK;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE_PTR pMechanismList,
                         CK_ULONG_PTR pulCount)
{
	struct sc_pkcs11_slot *slot;
        CK_RV rv;

	rv = slot_get_token(slotID, &slot);
	if (rv != CKR_OK)
		return rv;

	return slot->card->framework->get_mechanism_list(slot->card,
							 slot->fw_data,
							 pMechanismList,
							 pulCount);
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE type,
			 CK_MECHANISM_INFO_PTR pInfo)
{
	struct sc_pkcs11_slot *slot;
        CK_RV rv;

	rv = slot_get_token(slotID, &slot);
	if (rv != CKR_OK)
		return rv;

	return slot->card->framework->get_mechanism_info(slot->card,
							 slot->fw_data,
							 type,
							 pInfo);
}

CK_RV C_InitToken(CK_SLOT_ID slotID,
		  CK_CHAR_PTR pPin,
		  CK_ULONG ulPinLen,
		  CK_CHAR_PTR pLabel)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags,   /* blocking/nonblocking flag */
			 CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
			 CK_VOID_PTR pReserved) /* reserved.  Should be NULL_PTR */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



CK_FUNCTION_LIST pkcs11_function_list = {
	{ 2, 11 },
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	C_GetOperationState,
	C_SetOperationState,
	C_Login,
	C_Logout,
	C_CreateObject,
	C_CopyObject,
	C_DestroyObject,
	C_GetObjectSize,
	C_GetAttributeValue,
	C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
	C_EncryptUpdate,
	C_EncryptFinal,
	C_DecryptInit,
	C_Decrypt,
	C_DecryptUpdate,
	C_DecryptFinal,
        C_DigestInit,
	C_Digest,
	C_DigestUpdate,
	C_DigestKey,
	C_DigestFinal,
	C_SignInit,
	C_Sign,
	C_SignUpdate,
	C_SignFinal,
	C_SignRecoverInit,
	C_SignRecover,
	C_VerifyInit,
	C_Verify,
	C_VerifyUpdate,
	C_VerifyFinal,
	C_VerifyRecoverInit,
	C_VerifyRecover,
	C_DigestEncryptUpdate,
	C_DecryptDigestUpdate,
	C_SignEncryptUpdate,
	C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
	C_WrapKey,
	C_UnwrapKey,
	C_DeriveKey,
	C_SeedRandom,
	C_GenerateRandom,
	C_GetFunctionStatus,
        C_CancelFunction,
	C_WaitForSlotEvent
};


