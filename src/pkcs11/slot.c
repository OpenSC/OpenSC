/*
 * slot.c: smart card and slot related management functions
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

#include <string.h>
#include "sc-pkcs11.h"

static struct sc_pkcs11_framework_ops *frameworks[] = {
	&framework_pkcs15,
#ifdef USE_PKCS15_INIT
	/* This should be the last framework, because it
	 * will assume the card is blank and try to initialize it */
	&framework_pkcs15init,
#endif
	NULL
};

unsigned int first_free_slot = 0;

static void init_slot_info(CK_SLOT_INFO_PTR pInfo)
{
	strcpy_bp(pInfo->slotDescription, "Virtual slot", 64);
	strcpy_bp(pInfo->manufacturerID, "OpenSC (www.opensc-project.org)", 32);
	pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
	pInfo->hardwareVersion.major = 0;
	pInfo->hardwareVersion.minor = 0;
	pInfo->firmwareVersion.major = 0;
	pInfo->firmwareVersion.minor = 0;
}

CK_RV card_initialize(int reader)
{
	struct sc_pkcs11_card *card = card_table + reader;
	unsigned int avail;
	unsigned int i;

	if (reader < 0 || reader >= SC_MAX_READERS)
		return CKR_FUNCTION_FAILED;

	memset(card, 0, sizeof(struct sc_pkcs11_card));
	card->reader = reader;

	/* Always allocate a fixed slot range to one reader/card.
	 * Some applications get confused if readers pop up in
	 * different slots. */
	avail = sc_pkcs11_conf.slots_per_card;

	if (first_free_slot + avail > sc_pkcs11_conf.max_virtual_slots)
		avail = sc_pkcs11_conf.max_virtual_slots - first_free_slot;
	card->first_slot = first_free_slot;
	card->max_slots = avail;
	card->num_slots = 0;

	for (i = 0; i < card->max_slots; i++) {
		struct sc_pkcs11_slot *slot = virtual_slots + card->first_slot + i;
		slot->reader = reader;
	}

	first_free_slot += card->max_slots;
	return CKR_OK;
}

CK_RV card_detect(int reader)
{
	struct sc_pkcs11_card *card = &card_table[reader];
	int rc, rv, i, retry = 1;

	rv = CKR_OK;

	sc_debug(context, "%d: Detecting smart card\n", reader);
	for (i = card->max_slots; i--; ) {
		struct sc_pkcs11_slot *slot;
		sc_reader_t *rdr = sc_ctx_get_reader(context, (unsigned int)reader);

		if (rdr == NULL)
			return CKR_TOKEN_NOT_PRESENT;
		slot = virtual_slots + card->first_slot + i;
		strcpy_bp(slot->slot_info.slotDescription, rdr->name, 64);
		slot->reader = reader;
	}


	/* Check if someone inserted a card */
again:	rc = sc_detect_card_presence(sc_ctx_get_reader(context, reader), 0);
	if (rc < 0) {
		sc_debug(context, "Card detection failed for reader %d: %s\n",
				reader, sc_strerror(rc));
		return sc_to_cryptoki_error(rc, reader);
	}
	if (rc == 0) {
		sc_debug(context, "%d: Card absent\n", reader);
		card_removed(reader); /* Release all resources */
		return CKR_TOKEN_NOT_PRESENT;
	}

	/* If the card was changed, disconnect the current one */
	if (rc & SC_SLOT_CARD_CHANGED) {
		sc_debug(context, "%d: Card changed\n", reader);
		/* The following should never happen - but if it
		 * does we'll be stuck in an endless loop.
		 * So better be fussy. */
		if (!retry--)
			return CKR_TOKEN_NOT_PRESENT;
		card_removed(reader);
		goto again;
	}

	/* Detect the card if it's not known already */
	if (card->card == NULL) {
		sc_debug(context, "%d: Connecting to smart card\n", reader);
		rc = sc_connect_card(sc_ctx_get_reader(context, reader), 0, &card->card);
		if (rc != SC_SUCCESS)
			return sc_to_cryptoki_error(rc, reader);
	}

	/* Detect the framework */
	if (card->framework == NULL) {
		sc_debug(context, "%d: Detecting Framework\n", reader);

		for (i = 0; frameworks[i]; i++) {
			if (frameworks[i]->bind == NULL)
				continue;
			rv = frameworks[i]->bind(card);
			if (rv == CKR_OK)
				break;
		}

		if (frameworks[i] == NULL)
			return CKR_TOKEN_NOT_RECOGNIZED;

		/* Initialize framework */
		sc_debug(context, "%d: Detected framework %d. Creating tokens.\n", reader, i);
		rv = frameworks[i]->create_tokens(card);
		if (rv != CKR_OK)
			return rv;

		card->framework = frameworks[i];
	}

	sc_debug(context, "%d: Detection ended\n", reader);
	return rv;
}

CK_RV __card_detect_all(int report_events)
{
	int i;

	if (context == NULL_PTR)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	for (i = 0; i < (int)sc_ctx_get_reader_count(context); i++)
		card_detect(i);
	if (!report_events) {
		CK_SLOT_ID id;

		for (id = 0; id < sc_pkcs11_conf.max_virtual_slots; id++)
			virtual_slots[id].events = 0;
	}

	return CKR_OK;
}

CK_RV card_detect_all(void)
{
	return __card_detect_all(1);
}

CK_RV card_removed(int reader)
{
	unsigned int i;
	struct sc_pkcs11_card *card;

	sc_debug(context, "%d: smart card removed\n", reader);

	for (i=0; i<sc_pkcs11_conf.max_virtual_slots; i++) {
		if (virtual_slots[i].card &&
		    virtual_slots[i].card->reader == reader)
				slot_token_removed(i);
	}

	/* beware - do not clean the entire sc_pkcs11_card struct;
	 * fields such as first_slot and max_slots are initialized
	 * _once_ and need to be left untouched across card removal/
	 * insertion */
	card = &card_table[reader];
	if (card->framework)
		card->framework->unbind(card);
	card->framework = NULL;
	card->fw_data = NULL;

	if (card->card)
		sc_disconnect_card(card->card, 0);
	card->card = NULL;

	return CKR_OK;
}

CK_RV slot_initialize(int id, struct sc_pkcs11_slot *slot)
{
	memset(slot, 0, sizeof(*slot));
	slot->id = id;
	slot->login_user = -1;
	init_slot_info(&slot->slot_info);
	pool_initialize(&slot->object_pool, POOL_TYPE_OBJECT);

	return CKR_OK;
}

CK_RV slot_allocate(struct sc_pkcs11_slot **slot, struct sc_pkcs11_card *card)
{
	unsigned int i, first, last;

	if (card->num_slots >= card->max_slots)
		return CKR_FUNCTION_FAILED;
	first = card->first_slot;
	last  = first + card->max_slots;

	for (i = first; i < last; i++) {
		if (!virtual_slots[i].card) {
			sc_debug(context, "Allocated slot %d\n", i);
			virtual_slots[i].card = card;
			virtual_slots[i].events = SC_EVENT_CARD_INSERTED;
			*slot = &virtual_slots[i];
			card->num_slots++;
			return CKR_OK;
		}
	}
	return CKR_FUNCTION_FAILED;
}

CK_RV slot_get_slot(int id, struct sc_pkcs11_slot **slot)
{
	if (context == NULL)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (id < 0 || id >= sc_pkcs11_conf.max_virtual_slots)
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
	{
		rv = card_detect((*slot)->reader);
		if (rv != CKR_OK)
			return CKR_TOKEN_NOT_PRESENT;
	}

	if (!((*slot)->slot_info.flags & CKF_TOKEN_PRESENT))
	{
		sc_debug(context, "card detected, but slot not presenting token");
		return CKR_TOKEN_NOT_PRESENT;
	}
	return CKR_OK;
}

CK_RV slot_token_removed(int id)
{
	int rv, token_was_present;
	struct sc_pkcs11_slot *slot;
	struct sc_pkcs11_object *object;
	CK_SLOT_INFO saved_slot_info;
	int reader;

	rv = slot_get_slot(id, &slot);
	if (rv != CKR_OK)
		return rv;

	token_was_present = (slot->slot_info.flags & CKF_TOKEN_PRESENT);

	/* Terminate active sessions */
	sc_pkcs11_close_all_sessions(id);

	/* Object pool */
	while (pool_find_and_delete(&slot->object_pool, 0, (void**) &object) == CKR_OK) {
		if (object->ops->release)
			object->ops->release(object);
	}

	/* Release framework stuff */
	if (slot->card != NULL) {
		if (slot->fw_data != NULL &&
				slot->card->framework != NULL &&
				slot->card->framework->release_token != NULL)
			slot->card->framework->release_token(slot->card, slot->fw_data);
		slot->card->num_slots--;
	}

	/* Zap everything else. Restore the slot_info afterwards (it contains the reader
	 * name, for instance) but clear its flags */
	saved_slot_info = slot->slot_info;
	reader = slot->reader;
	memset(slot, 0, sizeof(*slot));
	slot->slot_info = saved_slot_info;
	slot->slot_info.flags = 0;
	slot->login_user = -1;
	slot->reader = reader;
	pool_initialize(&slot->object_pool, POOL_TYPE_OBJECT);

	if (token_was_present)
		slot->events = SC_EVENT_CARD_REMOVED;

	return CKR_OK;
}

CK_RV slot_find_changed(CK_SLOT_ID_PTR idp, int mask)
{
	sc_pkcs11_slot_t *slot;
	CK_SLOT_ID id;

	card_detect_all();
	for (id = 0; id < sc_pkcs11_conf.max_virtual_slots; id++) {
		slot = &virtual_slots[id];
		if ((slot->events & SC_EVENT_CARD_INSERTED)
		 && !(slot->slot_info.flags & CKF_TOKEN_PRESENT))
			slot->events &= ~SC_EVENT_CARD_INSERTED;
		if (slot->events & mask) {
			slot->events &= ~mask;
			*idp = id;
			return CKR_OK;
		}
	}
	return CKR_NO_EVENT;
}
