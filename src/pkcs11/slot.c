#include <stdio.h>
#include <malloc.h>
#include "sc-pkcs11.h"

void set_attribute(CK_ATTRIBUTE_PTR attr, CK_OBJECT_CLASS oc, void *ptr, int len)
{
	attr->type = oc;
	attr->pValue = malloc(len);
	memcpy(attr->pValue, ptr, len);
        attr->ulValueLen = len;
}

int slot_add_object(int id, CK_ATTRIBUTE_PTR object, int num_attrs)
{
	struct pkcs11_slot *slt = &slot[id];
	int idx;

	if (slt->num_objects >= PKCS11_MAX_OBJECTS)
                return CKR_BUFFER_TOO_SMALL;

	idx = ++slt->num_objects;
	slt->object[idx] = (struct pkcs11_object*) malloc(sizeof(struct pkcs11_object));
	slt->object[idx]->num_attributes = num_attrs;
	slt->object[idx]->attribute = object;

        return CKR_OK;
}

int slot_add_private_key_object(int id, struct sc_pkcs15_prkey_info *key)
{
	static CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE_PTR object = (CK_ATTRIBUTE_PTR) malloc(sizeof(CK_ATTRIBUTE) * 3);

        set_attribute(&object[0], CKA_CLASS, &key_class, sizeof(key_class));
        set_attribute(&object[1], CKA_LABEL, key->com_attr.label, strlen(key->com_attr.label));
	set_attribute(&object[2], CKA_ID,    key->id.value, key->id.len);

        return slot_add_object(id, object, 3);
}

int slot_add_certificate_object(int id, struct sc_pkcs15_cert_info *cert,
			        u8 *x509data, int x509length)
{
	static CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE_PTR object = (CK_ATTRIBUTE_PTR) malloc(sizeof(CK_ATTRIBUTE) * 4);

        set_attribute(&object[0], CKA_CLASS, &cert_class, sizeof(cert_class));
        set_attribute(&object[1], CKA_LABEL, cert->com_attr.label, strlen(cert->com_attr.label));
        set_attribute(&object[2], CKA_ID,    cert->id.value, cert->id.len);
	set_attribute(&object[3], CKA_VALUE, x509data, x509length);

        return slot_add_object(id, object, 4);
}

int slot_connect(int id)
{
	struct sc_card *card;
        struct sc_pkcs15_card *p15card;
	int r, c;

	r = sc_connect_card(ctx, id, &card);
	if (r) {
		LOG("Failed to connect in slot %d (r=%d)\n", id, r);
		return CKR_TOKEN_NOT_PRESENT;
	}

	r = sc_pkcs15_init(card, &slot[id].p15card);
	if (r) {
		LOG("sc_pkcs15_init failed for slot %d (r=%d)\n", id, r);
		/* PKCS#15 compatible SC probably not present */
		sc_disconnect_card(card);
		return CKR_TOKEN_NOT_RECOGNIZED;
	}

        p15card = slot[id].p15card;

	c = sc_pkcs15_enum_pins(p15card);
	// FIXME: c < 0 ==> error

	LOG("Found total of %d PIN codes.\n", c);
	slot[id].flags = SLOT_CONNECTED;
        slot[id].num_objects = 0;

	r = sc_pkcs15_enum_certificates(p15card);
	if (r < 0)
		return CKR_DEVICE_ERROR;

        LOG("Found total of %d certificates.\n", r);
	for (c = 0; c < r; c++) {
                int len;
		u8 *buf;

		LOG("Reading '%s' certificate.\n", p15card->cert_info[c].com_attr.label);
		len = sc_pkcs15_read_certificate(p15card, &p15card->cert_info[c], &buf);
		if (len < 0)
			return len;

		LOG("Adding '%s' certificate object.\n", p15card->cert_info[c].com_attr.label);
		slot_add_certificate_object(id, &p15card->cert_info[c],
					    buf, len);
	}

	r = sc_pkcs15_enum_private_keys(p15card);
	if (r < 0)
            return CKR_DEVICE_ERROR;

        LOG("Found total of %d private keys.\n", r);
	for (c = 0; c < r; c++) {
		LOG("Adding '%s' private key object.\n", p15card->prkey_info[c].com_attr.label);
		slot_add_private_key_object(id, &p15card->prkey_info[c]);
	}

        return CKR_OK;
}

int slot_disconnect(int id)
{
        LOG("Disconnecting from slot %d\n", id);
        slot[id].flags = 0;
	if (slot[id].p15card != NULL) {
		sc_disconnect_card(slot[id].p15card->card);
		sc_pkcs15_destroy(slot[id].p15card);
		slot[id].p15card = NULL;
	}

	return CKR_OK;
}

