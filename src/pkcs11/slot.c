#include <stdio.h>
#include <malloc.h>
#include "sc-pkcs11.h"

static CK_BYTE modulus[] =
#if 0
                    "\x00\xc7\x50\xbb\x9e\xf7\x43\x18\x7e\x8d\xb5\xe3\xa1\x6e\x4c"
		    "\x8c\x0f\x0f\xc7\x9a\xce\xad\x05\x1b\x16\xf0\x30\x25\xdb\x1f"
                    "\xbd\xf3\x68\x76\x29\xee\x75\x97\xba\x20\x1a\x48\xa8\x55\xa1"
                    "\x50\x91\x45\x0e\x64\x70\xcd\xda\x52\x0b\x67\x94\x16\x89\x73"
                    "\x7d\xa1\x7c\x5b\xa9\x29\xd8\xe2\x38\xc8\x24\x73\xaa\xc1\x7a"
                    "\x99\x6f\x4f\xe9\xa6\xcc\x9e\x02\xd4\xb2\xf1\xf5\xe5\x94\x1f"
                    "\x30\x70\x6c\x29\xe6\x65\x06\x55\x67\xc5\xa7\x35\x82\x5c\x6d"
                    "\x4d\xe7\x60\x83\xf4\x0c\xed\xbe\x6b\xb1\xc3\xe4\x55\x99\x7f"
		    "\x79\x07\x99\x2f\x65\x8b\xe5\x89\xe5";
#else
                    "\x00\xba\xb3\xc3\x65\xfb\xab\xd3\x4f\xf1\xe8\x72\xb8\xaa\x48"
                    "\x6a\x82\x31\x43\xc9\x3e\xe6\xff\x6b\xb6\x0e\xa3\x82\xb4\xda"
                    "\x3f\xed\xa6\x0b\xbc\xf2\xd3\xad\x53\x88\x88\x14\x14\x3f\x2b"
                    "\x24\x8d\xd7\x3f\x4b\xb3\xe6\xc1\xb9\xb1\x4d\x3a\x10\xc4\x65"
                    "\xdc\xe2\xa1\x27\xd2\x8f\xb2\x67\x54\x34\x73\x53\xeb\xec\x84"
                    "\xab\xdd\xc1\x76\xc9\x73\x49\x4c\x7c\x18\x98\xd3\x40\xc4\x1c"
                    "\xfd\x0d\x6b\xae\xb7\x9f\x44\xc6\x0a\x5a\x89\x91\xb8\x6e\x20"
                    "\x38\x2b\xff\x42\xf7\xfe\x95\xc0\x1f\xa5\xca\x07\x2e\x4a\xb0"
                    "\x9c\x07\x60\x02\x61\xe1\x8b\x25\x01";
#endif


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

int slot_add_private_key_object(int id, int token_id, struct sc_pkcs15_prkey_info *key)
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
        set_attribute(&object[5], CKA_MODULUS, modulus, sizeof(modulus)-1);

        return slot_add_object(id, token_id, object, 6);
}

int slot_add_certificate_object(int id, int token_id,
				struct sc_pkcs15_cert_info *cert,
			        u8 *x509data, int x509length)
{
	static CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE_PTR object = (CK_ATTRIBUTE_PTR) malloc(sizeof(CK_ATTRIBUTE) * 4);

        set_attribute(&object[0], CKA_CLASS, &cert_class, sizeof(cert_class));
        set_attribute(&object[1], CKA_LABEL, cert->com_attr.label, strlen(cert->com_attr.label));
        set_attribute(&object[2], CKA_ID,    cert->id.value, cert->id.len);
	set_attribute(&object[3], CKA_VALUE, x509data, x509length);

        return slot_add_object(id, token_id, object, 4);
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
		slot_add_certificate_object(id, c, &p15card->cert_info[c],
					    buf, len);
	}

	r = sc_pkcs15_enum_private_keys(p15card);
	if (r < 0)
            return CKR_DEVICE_ERROR;

        LOG("Found total of %d private keys.\n", r);
	for (c = 0; c < r; c++) {
		LOG("Adding '%s' private key object.\n", p15card->prkey_info[c].com_attr.label);
		slot_add_private_key_object(id, c, &p15card->prkey_info[c]);
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

