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

#include <stdlib.h>
#include <string.h>
#include "sc-pkcs11.h"

struct sc_context *context = NULL;
struct sc_pkcs11_pool session_pool;
struct sc_pkcs11_slot virtual_slots[SC_PKCS11_MAX_VIRTUAL_SLOTS];
struct sc_pkcs11_card card_table[SC_PKCS11_MAX_READERS];
struct sc_pkcs11_config sc_pkcs11_conf;

extern CK_FUNCTION_LIST pkcs11_function_list;

CK_RV C_Initialize(CK_VOID_PTR pReserved)
{
	int i, rc, rv;

	if (context != NULL) {
		error(context, "C_Initialize(): Cryptoki already initialized\n");
                return CKR_CRYPTOKI_ALREADY_INITIALIZED;
	}
	rc = sc_establish_context(&context, "opensc-pkcs11");
	if (rc != 0) {
		rv = CKR_DEVICE_ERROR;
		goto out;
	}

	/* Load configuration */
	load_pkcs11_parameters(&sc_pkcs11_conf, context);

	first_free_slot = 0;
        pool_initialize(&session_pool, POOL_TYPE_SESSION);
	for (i=0; i<SC_PKCS11_MAX_VIRTUAL_SLOTS; i++)
                slot_initialize(i, &virtual_slots[i]);
	for (i=0; i<SC_PKCS11_MAX_READERS; i++)
                card_initialize(i);

	/* Detect any card, but do not flag "insert" events */
	__card_detect_all(0);

	rv = sc_pkcs11_init_lock((CK_C_INITIALIZE_ARGS_PTR) pReserved);

out:	debug(context, "C_Initialize: result = %d\n", rv);
	return rv;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	int i;
	CK_RV rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	if (pReserved != NULL)
		return CKR_ARGUMENTS_BAD;

	debug(context, "Shutting down Cryptoki\n");
	for (i=0; i<context->reader_count; i++)
                card_removed(i);

	sc_release_context(context);
	context = NULL;
	sc_pkcs11_unlock();
	sc_pkcs11_free_lock();

        return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	CK_RV rv = CKR_OK;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	if (pInfo == NULL_PTR) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}

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

out:	sc_pkcs11_unlock();
        return rv;
}	

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (ppFunctionList == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &pkcs11_function_list;
	return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL       tokenPresent,  /* only slots with token present */
		    CK_SLOT_ID_PTR pSlotList,     /* receives the array of slot IDs */
		    CK_ULONG_PTR   pulCount)      /* receives the number of slots */
{
	CK_SLOT_ID found[SC_PKCS11_MAX_VIRTUAL_SLOTS];
	int numMatches, i;
	sc_pkcs11_slot_t *slot;
	CK_RV rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	if (pulCount == NULL_PTR) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}

	debug(context, "Getting slot listing\n");
	card_detect_all();

	numMatches = 0;
	for (i=0; i<SC_PKCS11_MAX_VIRTUAL_SLOTS; i++) {
		slot = &virtual_slots[i];

		if (!tokenPresent || (slot->slot_info.flags & CKF_TOKEN_PRESENT))
			found[numMatches++] = i;
	}

	if (pSlotList == NULL_PTR) {
		debug(context, "was only a size inquiry (%d)\n", numMatches);
		*pulCount = numMatches;
                rv = CKR_OK;
		goto out;
	}

	if (*pulCount < numMatches) {
		debug(context, "buffer was too small (needed %d)\n", numMatches);
		*pulCount = numMatches;
                rv = CKR_BUFFER_TOO_SMALL;
		goto out;
	}

	memcpy(pSlotList, found, numMatches * sizeof(CK_SLOT_ID));
	*pulCount = numMatches;
	rv = CKR_OK;

	debug(context, "returned %d slots\n", numMatches);

out:	sc_pkcs11_unlock();
        return rv;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	struct sc_pkcs11_slot *slot;
        CK_RV rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	if (pInfo == NULL_PTR) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}

	debug(context, "Getting info about slot %d\n", slotID);

	rv = slot_get_slot(slotID, &slot);
	if (rv == CKR_OK)
		rv = card_detect(slot->reader);
	if (rv == CKR_TOKEN_NOT_PRESENT)
		return CKR_OK;

	if (rv == CKR_OK)
		memcpy(pInfo, &slot->slot_info, sizeof(CK_SLOT_INFO));

out:	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	struct sc_pkcs11_slot *slot;
        CK_RV rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	if (pInfo == NULL_PTR) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}

	debug(context, "Getting info about token in slot %d\n", slotID);

	rv = slot_get_token(slotID, &slot);
	if (rv == CKR_OK)
		memcpy(pInfo, &slot->token_info, sizeof(CK_TOKEN_INFO));

out:	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE_PTR pMechanismList,
                         CK_ULONG_PTR pulCount)
{
	struct sc_pkcs11_slot *slot;
        CK_RV rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = slot_get_token(slotID, &slot);
	if (rv == CKR_OK)
		rv = sc_pkcs11_get_mechanism_list(slot->card, pMechanismList, pulCount);

	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE type,
			 CK_MECHANISM_INFO_PTR pInfo)
{
	struct sc_pkcs11_slot *slot;
        CK_RV rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	if (pInfo == NULL_PTR) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}
	rv = slot_get_token(slotID, &slot);
	if (rv == CKR_OK)
		rv = sc_pkcs11_get_mechanism_info(slot->card, type, pInfo);

out:	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_InitToken(CK_SLOT_ID slotID,
		  CK_CHAR_PTR pPin,
		  CK_ULONG ulPinLen,
		  CK_CHAR_PTR pLabel)
{
	struct sc_pkcs11_pool_item *item;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_slot *slot;
        CK_RV rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = slot_get_token(slotID, &slot);
	if (rv != CKR_OK)
		goto out;

	/* Make sure there's no open session for this token */
	for (item = session_pool.head; item; item = item->next) {
		session = (struct sc_pkcs11_session*) item->item;
		if (session->slot == slot) {
			rv = CKR_SESSION_EXISTS;
			goto out;
		}
	}

	if (slot->card->framework->init_token == NULL)
		return CKR_FUNCTION_NOT_SUPPORTED;
	rv = slot->card->framework->init_token(slot->card,
				 slot->fw_data, pPin, ulPinLen, pLabel);

	if (rv == CKR_OK) {
		/* Now we should re-bind all tokens so they get the
		 * corresponding function vector and flags */
	}

out:	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags,   /* blocking/nonblocking flag */
			 CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
			 CK_VOID_PTR pReserved) /* reserved.  Should be NULL_PTR */
{
	struct sc_reader *reader, *readers[SC_MAX_SLOTS * SC_MAX_READERS];
	int slots[SC_MAX_SLOTS * SC_MAX_READERS];
	int i, j, k, r, found;
	unsigned int mask, events;
	CK_RV rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	if (pReserved != NULL_PTR) {
		rv = CKR_ARGUMENTS_BAD;
		goto out;
	}

	mask = SC_EVENT_CARD_INSERTED|SC_EVENT_CARD_REMOVED;

	if ((rv = slot_find_changed(pSlot, mask)) == CKR_OK
	 || (flags & CKF_DONT_BLOCK))
		goto out;

	for (i = k = 0; i < context->reader_count; i++) {
		reader = context->reader[i];
		for (j = 0; j < reader->slot_count; j++, k++) {
			readers[k] = reader;
			slots[k] = j;
		}
	}

	sc_pkcs11_unlock();
	r = sc_wait_for_event(readers, slots, k, mask, &found, &events, -1);
	sc_pkcs11_lock();

	if (r != SC_SUCCESS) {
		error(context, "sc_wait_for_event() returned %d\n",  r);
		rv = sc_to_cryptoki_error(r, -1);
		goto out;
	}

	if ((rv = slot_find_changed(pSlot, mask)) != CKR_OK)
		rv = CKR_FUNCTION_FAILED;

out:	sc_pkcs11_unlock();
	return rv;
}

/*
 * Locking functions
 */
#include "../libopensc/internal.h"

static CK_C_INITIALIZE_ARGS_PTR	_locking;
static void *			_lock = NULL;

CK_RV
sc_pkcs11_init_lock(CK_C_INITIALIZE_ARGS_PTR args)
{
	int rv = CKR_OK;

	if (_lock)
		return CKR_OK;

	/* No CK_C_INITIALIZE_ARGS pointer, no locking */
	if (!args)
		return CKR_OK;

	if (args->pReserved)
		return CKR_ARGUMENTS_BAD;

	/* If the app tells us OS locking is okay,
	 * use that. Otherwise use the supplied functions.
	 */
	_locking = NULL;
	if (args->flags & CKF_OS_LOCKING_OK) {
		if (!(_lock = sc_mutex_new()))
			rv = CKR_CANT_LOCK;
	} else
	if (args->CreateMutex
	 && args->DestroyMutex
	 && args->LockMutex
	 && args->UnlockMutex) {
		rv = args->CreateMutex(&_lock);
		if (rv == CKR_OK)
			_locking = args;
	}

	return rv;
}

void
sc_pkcs11_free_lock()
{
	if (!_lock)
		return;
	if (_locking)
		_locking->DestroyMutex(_lock);
	else
		sc_mutex_free((sc_mutex_t *) _lock);
	_locking = NULL;
	_lock = NULL;
}

CK_RV
sc_pkcs11_lock()
{
	if (context == NULL)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!_lock)
		return CKR_OK;
	if (_locking)  {
		while (_locking->LockMutex(_lock) != CKR_OK)
			;
	} else {
		sc_mutex_lock((sc_mutex_t *) _lock);
	}

	return CKR_OK;
}

void
sc_pkcs11_unlock()
{
	if (!_lock)
		return;
	if (_locking) {
		while (_locking->UnlockMutex(_lock) != CKR_OK)
			;
	} else {
		sc_mutex_unlock((sc_mutex_t *) _lock);
	}
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
