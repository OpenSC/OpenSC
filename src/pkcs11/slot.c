/*
 * slot.c: Internal functions to ease slot management
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
#include <stdlib.h>
#include <malloc.h>
#include "sc-pkcs11.h"

void set_attribute(CK_ATTRIBUTE_PTR attr, CK_OBJECT_CLASS oc, void *ptr, int len)
{
	attr->type = oc;
	attr->pValue = malloc(len);
	memcpy(attr->pValue, ptr, len);
        attr->ulValueLen = len;
}

int slot_add_object(int id, int token_id, CK_ATTRIBUTE_PTR object, int num_attrs)
{
	struct pkcs11_slot *slt = &slot[id];
	int idx, i;

	if (slt->num_objects >= PKCS11_MAX_OBJECTS)
                return CKR_BUFFER_TOO_SMALL;

	idx = ++slt->num_objects;
	slt->object[idx] = (struct pkcs11_object*) malloc(sizeof(struct pkcs11_object));
	slt->object[idx]->object_type = -1;
        slt->object[idx]->token_id = token_id;
	slt->object[idx]->num_attributes = num_attrs;
	slt->object[idx]->attribute = object;

	for (i = 0; i < num_attrs; i++) {
		if (object[i].type == CKA_CLASS && object[i].ulValueLen == 4) {
			slt->object[idx]->object_type = *(int*)object[i].pValue;
                        break;
		}
	}

        return CKR_OK;
}

int slot_add_private_key_object(int id, int token_id, struct sc_pkcs15_prkey_info *key,
				struct sc_pkcs15_cert *cert)
{
	static CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
	static CK_BBOOL btrue = 1;
	static CK_KEY_TYPE rsakey = CKK_RSA;
	CK_ATTRIBUTE_PTR object = (CK_ATTRIBUTE_PTR) malloc(sizeof(CK_ATTRIBUTE) * 6);

        set_attribute(&object[0], CKA_CLASS, &key_class, sizeof(key_class));
        set_attribute(&object[1], CKA_LABEL, key->com_attr.label, strlen(key->com_attr.label));
	set_attribute(&object[2], CKA_ID,    key->id.value, key->id.len);
	set_attribute(&object[3], CKA_TOKEN, &btrue, sizeof(btrue));
	set_attribute(&object[4], CKA_KEY_TYPE, &rsakey, sizeof(rsakey));
        set_attribute(&object[5], CKA_MODULUS, cert->key.modulus, cert->key.modulus_len);

        return slot_add_object(id, token_id, object, 6);
}

int slot_add_certificate_object(int id, int token_id,
				struct sc_pkcs15_cert_info *info,
			        struct sc_pkcs15_cert *cert)
{
	static CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE_PTR object = (CK_ATTRIBUTE_PTR) malloc(sizeof(CK_ATTRIBUTE) * 4);

        set_attribute(&object[0], CKA_CLASS, &cert_class, sizeof(cert_class));
        set_attribute(&object[1], CKA_LABEL, info->com_attr.label, strlen(info->com_attr.label));
        set_attribute(&object[2], CKA_ID,    info->id.value, info->id.len);
	set_attribute(&object[3], CKA_VALUE, cert->data, cert->data_len);
	/* FIXME: save cert object */
	
        return slot_add_object(id, token_id, object, 4);
}

int slot_connect(int id)
{
	struct sc_card *card;
        struct sc_pkcs15_card *p15card;
	int r, c, i;

	r = sc_connect_card(ctx, id, &card);
	if (r) {
		LOG("Failed to connect in slot %d (r=%d)\n", id, r);
		return CKR_TOKEN_NOT_PRESENT;
	}

	r = sc_pkcs15_bind(card, &slot[id].p15card);
	if (r) {
		LOG("sc_pkcs15_init failed for slot %d (r=%d)\n", id, r);
		/* PKCS#15 compatible SC probably not present */
		sc_disconnect_card(card);
		return CKR_TOKEN_NOT_RECOGNIZED;
	}

        p15card = slot[id].p15card;

	c = sc_pkcs15_enum_pins(p15card);
	/* FIXME: c < 0 ==> error */

	LOG("Found total of %d PIN codes.\n", c);
	slot[id].flags = SLOT_CONNECTED;
        slot[id].num_objects = 0;

	r = sc_pkcs15_enum_certificates(p15card);
	if (r < 0)
		return CKR_DEVICE_ERROR;
        LOG("Found total of %d certificates.\n", p15card->cert_count);

	r = sc_pkcs15_enum_private_keys(p15card);
	if (r < 0)
            return CKR_DEVICE_ERROR;
        LOG("Found total of %d private keys.\n", p15card->prkey_count);

	for (c = 0; c < p15card->cert_count; c++) {
		struct sc_pkcs15_cert *cert;
		struct sc_pkcs15_cert_info *cinfo = &p15card->cert_info[c];

		LOG("Reading '%s' certificate.\n", cinfo->com_attr.label);
		r = sc_pkcs15_read_certificate(p15card, cinfo, &cert);
		if (r)
			return r;
		LOG("Adding '%s' certificate object (id %X).\n",
		    cinfo->com_attr.label, cinfo->id);
		slot_add_certificate_object(id, c, cinfo, cert);
		
		for (i = 0; i < p15card->prkey_count; i++) {
			struct sc_pkcs15_prkey_info *pinfo = &p15card->prkey_info[i];
			if (sc_pkcs15_compare_id(&cinfo->id, &pinfo->id)) {
				LOG("Adding '%s' private key object (id %X).\n", 
				    pinfo->com_attr.label, pinfo->id.value[0]);
				if (slot_add_private_key_object(id, i, pinfo, cert))
					LOG("Private key addition failed.\n");
			}
		}
		sc_pkcs15_free_certificate(cert);
	}

        return CKR_OK;
}

int slot_disconnect(int id)
{
        LOG("Disconnecting from slot %d\n", id);
        slot[id].flags = 0;
	if (slot[id].p15card != NULL) {
		struct sc_card *card = slot[id].p15card->card;
		
		sc_pkcs15_unbind(slot[id].p15card);
		sc_disconnect_card(card);
		slot[id].p15card = NULL;
	}

	return CKR_OK;
}

