/*
 * slot.c: Smartcard and slot related management functions
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

static struct sc_pkcs11_framework_ops *frameworks[] = {
        &framework_pkcs15,
	NULL
};

void clear_slot_info(CK_SLOT_INFO_PTR pInfo)
{
	strcpy_bp(pInfo->slotDescription, "Virtual slot", 64);
	strcpy_bp(pInfo->manufacturerID, "OpenSC project (www.opensc.org)", 32);
	pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
	pInfo->hardwareVersion.major = 0;
	pInfo->hardwareVersion.minor = 0;
	pInfo->firmwareVersion.major = 0;
        pInfo->firmwareVersion.minor = 0;
}

CK_RV card_initialize(int reader)
{
	memset(&card_table[reader], 0, sizeof(struct sc_pkcs11_card));
	card_table[reader].reader = reader;
        return CKR_OK;
}

CK_RV card_detect(int reader)
{
        int rc, rv, i;

        rv = CKR_OK;

	debug(context, "%d: Detecting SmartCard\n", reader);

	/* Already known to be present? */
	if (card_table[reader].card == NULL) {
		/* Check if someone inserted a card */
		if (sc_detect_card_presence(context->reader[reader], 0) != 1) {
			debug(context, "%d: Card absent\n", reader);
			return CKR_TOKEN_NOT_PRESENT;
		}

		/* Detect the card */
		debug(context, "%d: Connecting to SmartCard\n", reader);
		rc = sc_connect_card(context->reader[reader], 0, &card_table[reader].card);
		if (rc != SC_SUCCESS)
			return sc_to_cryptoki_error(rc, reader);
	}

	/* Detect the framework */
	if (card_table[reader].framework == NULL) {
		debug(context, "%d: Detecting Framework\n", reader);

		i = 0;
		while (frameworks[i] != NULL) {
			rv = frameworks[i]->bind(&card_table[reader]);
			if (rv == CKR_OK)
				break;
		}

		if (frameworks[i] == NULL)
			return CKR_TOKEN_NOT_RECOGNIZED;

		/* Initialize framework */
		debug(context, "%d: Detected framework %d. Creating tokens.\n", reader, i);
		rv = frameworks[i]->create_tokens(&card_table[reader]);
		if (rv != CKR_OK)
                        return rv;

		card_table[reader].framework = frameworks[i];
	}

	debug(context, "%d: Detection ended\n", reader);
	return rv;
}

CK_RV card_removed(int reader)
{
	int i;
        struct sc_pkcs11_card *card;

	debug(context, "%d: SmartCard removed\n", reader);

	for (i=0; i<SC_PKCS11_MAX_VIRTUAL_SLOTS; i++) {
		if (virtual_slots[i].card &&
		    virtual_slots[i].card->reader == reader)
                        slot_token_removed(i);
	}

	card = &card_table[reader];
	card->framework->unbind(card);
	card->framework = NULL;
	card->fw_data = NULL;

	sc_disconnect_card(card->card, 0);
        card->card = NULL;

        return CKR_OK;
}

CK_RV slot_initialize(int id, struct sc_pkcs11_slot *slot)
{
        memset(slot, 0, sizeof(slot));
	slot->id = id;
	slot->login_user = -1;
        clear_slot_info(&slot->slot_info);
	pool_initialize(&slot->object_pool);

        return CKR_OK;
}

CK_RV slot_allocate(struct sc_pkcs11_slot **slot, struct sc_pkcs11_card *card)
{
        int i;
	for (i=0; i<SC_PKCS11_MAX_VIRTUAL_SLOTS; i++) {
		if (!(virtual_slots[i].slot_info.flags & CKF_TOKEN_PRESENT)) {
			debug(context, "Allocated slot %d\n", i);

                        virtual_slots[i].slot_info.flags |= CKF_TOKEN_PRESENT;
                        virtual_slots[i].card = card;
			*slot = &virtual_slots[i];
                        return CKR_OK;
		}
	}
        return CKR_FUNCTION_FAILED;

}

CK_RV slot_get_slot(int id, struct sc_pkcs11_slot **slot)
{
	if (context == NULL)
                return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (id < 0 || id >= SC_PKCS11_MAX_VIRTUAL_SLOTS)
		return CKR_SLOT_ID_INVALID;

        *slot = &virtual_slots[id];
        return CKR_OK;
}

CK_RV slot_get_token(int id, struct sc_pkcs11_slot **slot)
{
	int rv;

	rv = slot_get_slot(id, slot);
	if (rv != CKR_OK)
		return rv;

	if (!((*slot)->slot_info.flags & CKF_TOKEN_PRESENT))
		return CKR_TOKEN_NOT_PRESENT;

        return CKR_OK;
}

CK_RV slot_token_removed(int id)
{
	int rv;
        struct sc_pkcs11_slot *slot;
        struct sc_pkcs11_object *object;

        rv = slot_get_token(id, &slot);
	if (rv != CKR_OK)
		return rv;

        /* Terminate active sessions */
        C_CloseAllSessions(id);

	/* Object pool */
	while (pool_find_and_delete(&slot->object_pool, 0, (void**) &object) == CKR_OK) {
                if (object->ops->release)
			object->ops->release(object);
	}

	/* Release framework stuff */
	if (slot->card != NULL && slot->fw_data != NULL) {
		slot->card->framework->release_token(slot->card, slot->fw_data);

		slot->card = NULL;
		slot->fw_data = NULL;
	}

        /* Zap everything else */
	slot->login_user = -1;
	clear_slot_info(&slot->slot_info);

        return CKR_OK;

}

