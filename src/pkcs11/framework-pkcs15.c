/*
 * framework-pkcs15.c: PKCS#15 framework and related objects
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
#ifdef USE_PKCS15_INIT
#include "opensc/pkcs15-init.h"
#endif

#define MAX_CACHE_PIN		32
struct pkcs15_slot_data {
	struct sc_pkcs15_object *auth_obj;
	struct {
		u8		value[MAX_CACHE_PIN];
		unsigned int	len;
	}			pin[2];
};
#define slot_data(p)		((struct pkcs15_slot_data *) p)
#define slot_data_auth(p)	(slot_data(p)->auth_obj)
#define slot_data_pin_info(p)	(slot_data_auth(p)? \
		(struct sc_pkcs15_pin_info *) slot_data_auth(p)->data : NULL)

#define check_attribute_buffer(attr,size)	\
	if (attr->pValue == NULL_PTR) {         \
		attr->ulValueLen = size;        \
		return CKR_OK;                  \
	}                                       \
	if (attr->ulValueLen < size) {		\
		attr->ulValueLen = size;	\
		return CKR_BUFFER_TOO_SMALL;    \
	}                                       \
        attr->ulValueLen = size;

#define MAX_OBJECTS	64
struct pkcs15_fw_data {
	struct sc_pkcs15_card *		p15_card;
	struct pkcs15_any_object *	objects[MAX_OBJECTS];
	unsigned int			num_objects;
	unsigned int			locked;
};

struct pkcs15_any_object {
	struct sc_pkcs11_object		base;
	unsigned int			refcount;
	size_t				size;
	struct sc_pkcs15_object *	p15_object;
	struct pkcs15_pubkey_object *	related_pubkey;
	struct pkcs15_cert_object *	related_cert;
	struct pkcs15_prkey_object *	related_privkey;
};

struct pkcs15_cert_object {
	struct pkcs15_any_object	base;

	struct sc_pkcs15_cert_info *	cert_info;
        struct sc_pkcs15_cert *		cert_data;
};
#define cert_flags		base.base.flags
#define cert_p15obj		base.p15_object
#define cert_pubkey		base.related_pubkey
#define cert_issuer		base.related_cert

struct pkcs15_prkey_object {
	struct pkcs15_any_object	base;

	struct sc_pkcs15_prkey_info *	prv_info;
};
#define prv_flags		base.base.flags
#define prv_p15obj		base.p15_object
#define prv_pubkey		base.related_pubkey
#define prv_cert		base.related_cert
#define prv_next		base.related_privkey

struct pkcs15_pubkey_object {
	struct pkcs15_any_object	base;

	struct sc_pkcs15_pubkey_info *	pub_info;	/* NULL for key extracted from cert */
	struct sc_pkcs15_pubkey *	pub_data;
};
#define pub_flags		base.base.flags
#define pub_p15obj		base.p15_object
#define pub_cert		base.related_cert

#define __p15_type(obj)		(((obj) && (obj)->p15_object)? ((obj)->p15_object->type) : -1)
#define is_privkey(obj)		(__p15_type(obj) == SC_PKCS15_TYPE_PRKEY_RSA)
#define is_pubkey(obj)		(__p15_type(obj) == SC_PKCS15_TYPE_PUBKEY_RSA)
#define is_cert(obj)		(__p15_type(obj) == SC_PKCS15_TYPE_CERT_X509)

extern struct sc_pkcs11_object_ops pkcs15_cert_ops;
extern struct sc_pkcs11_object_ops pkcs15_prkey_ops;
extern struct sc_pkcs11_object_ops pkcs15_pubkey_ops;


static int	__pkcs15_release_object(struct pkcs15_any_object *);
static int	register_mechanisms(struct sc_pkcs11_card *p11card);
static CK_RV	get_public_exponent(struct sc_pkcs15_pubkey *,
					CK_ATTRIBUTE_PTR);
static CK_RV	get_modulus(struct sc_pkcs15_pubkey *,
					CK_ATTRIBUTE_PTR);
static CK_RV	get_modulus_bits(struct sc_pkcs15_pubkey *,
					CK_ATTRIBUTE_PTR);
static CK_RV	get_usage_bit(unsigned int usage, CK_ATTRIBUTE_PTR attr);
static CK_RV	asn1_sequence_wrapper(const u8 *, size_t, CK_ATTRIBUTE_PTR);
static void	cache_pin(void *, int, const void *, size_t);
static int	revalidate_pin(struct pkcs15_slot_data *data,
				struct sc_pkcs11_session *ses);
static int	lock_card(struct pkcs15_fw_data *);
static int	unlock_card(struct pkcs15_fw_data *);

/* PKCS#15 Framework */

static CK_RV pkcs15_bind(struct sc_pkcs11_card *p11card)
{
	struct pkcs15_fw_data *fw_data;
	int rc;

	if (!(fw_data = (struct pkcs15_fw_data *) calloc(1, sizeof(*fw_data))))
		return CKR_HOST_MEMORY;
	p11card->fw_data = fw_data;

	rc = sc_pkcs15_bind(p11card->card, &fw_data->p15_card);
	sc_debug(context, "Binding to PKCS#15, rc=%d\n", rc);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, p11card->reader);
	return register_mechanisms(p11card);
}

static CK_RV pkcs15_unbind(struct sc_pkcs11_card *p11card)
{
        struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	unsigned int i;
	int rc;

	for (i = 0; i < fw_data->num_objects; i++) 
		__pkcs15_release_object(fw_data->objects[i]);

	unlock_card(fw_data);

	rc = sc_pkcs15_unbind(fw_data->p15_card);
        return sc_to_cryptoki_error(rc, p11card->reader);
}

static void pkcs15_init_token_info(struct sc_pkcs15_card *card, CK_TOKEN_INFO_PTR pToken)
{
	int sn_start = strlen(card->serial_number) - 16;
	strcpy_bp(pToken->manufacturerID, card->manufacturer_id, 32);
	strcpy_bp(pToken->model, "PKCS #15 SCard", 16);
	/* Take the last 16 chars of the serial number (if the are more then 16).
	   _Assuming_ that the serial number is a Big Endian counter, this will
	   assure that the serial within each type of card will be unique in pkcs11
	   (at least for the first 16^16 cards :-) */
	if (sn_start < 0)
		sn_start = 0;
	strcpy_bp(pToken->serialNumber, card->serial_number + sn_start, 16);
	pToken->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	pToken->ulSessionCount = 0; /* FIXME */
	pToken->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	pToken->ulRwSessionCount = 0; /* FIXME */
	pToken->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->hardwareVersion.major = 1;
	pToken->hardwareVersion.minor = 0;
	pToken->firmwareVersion.major = 1;
	pToken->firmwareVersion.minor = 0;
}

static int
__pkcs15_create_object(struct pkcs15_fw_data *fw_data,
		       struct pkcs15_any_object **result,
		       struct sc_pkcs15_object *p15_object,
		       struct sc_pkcs11_object_ops *ops,
		       size_t size)
{
	struct pkcs15_any_object *obj;

	if (fw_data->num_objects >= MAX_OBJECTS)
		return SC_ERROR_TOO_MANY_OBJECTS;

	if (!(obj = (struct pkcs15_any_object *) calloc(1, size)))
		return SC_ERROR_OUT_OF_MEMORY;

	fw_data->objects[fw_data->num_objects++] = obj;

	obj->base.ops = ops;
	obj->p15_object = p15_object;
	obj->refcount = 1;
	obj->size = size;

	*result = obj;
	return 0;
}

static int
__pkcs15_release_object(struct pkcs15_any_object *obj)
{
	if (--(obj->refcount) != 0)
		return obj->refcount;
	
	memset(obj, 0xAA, obj->size);
	free(obj);

	return 0;
}

static int
__pkcs15_create_cert_object(struct pkcs15_fw_data *fw_data,
	struct sc_pkcs15_object *cert, struct pkcs15_any_object **cert_object)
{
	struct sc_pkcs15_cert_info *p15_info;
	struct sc_pkcs15_cert *p15_cert;
	struct pkcs15_cert_object *object;
        struct pkcs15_pubkey_object *obj2;
	int rv;

	p15_info = (struct sc_pkcs15_cert_info *) cert->data;
	if ((rv = sc_pkcs15_read_certificate(fw_data->p15_card, p15_info, &p15_cert) < 0))
		return rv;

        /* Certificate object */
	rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &object,
					cert, &pkcs15_cert_ops,
					sizeof(struct pkcs15_cert_object));
	if (rv < 0)
		return rv;

	object->cert_info = p15_info;
	object->cert_data = p15_cert;

        /* Corresponding public key */
	rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &obj2,
					NULL, &pkcs15_pubkey_ops,
					sizeof(struct pkcs15_pubkey_object));
	if (rv < 0)
		return rv;

	obj2->pub_data = &p15_cert->key;
	obj2->pub_cert = object;
	object->cert_pubkey = obj2;

	if (cert_object != NULL)
		*cert_object = (struct pkcs15_any_object *) object;

	return 0;
}

static int
__pkcs15_create_pubkey_object(struct pkcs15_fw_data *fw_data,
	struct sc_pkcs15_object *pubkey, struct pkcs15_any_object **pubkey_object)
{
	struct pkcs15_pubkey_object *object;
	struct sc_pkcs15_pubkey *p15_key;
	int rv;

	/* Read public key from card */
	if ((rv = sc_pkcs15_read_pubkey(fw_data->p15_card, pubkey, &p15_key)) < 0)
		return rv;

        /* Public key object */
	rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &object,
					pubkey, &pkcs15_pubkey_ops,
					sizeof(struct pkcs15_pubkey_object));
	if (rv >= 0) {
		object->pub_info = (struct sc_pkcs15_pubkey_info *) pubkey->data;
		object->pub_data = p15_key;
	}

	if (pubkey_object != NULL)
		*pubkey_object = (struct pkcs15_any_object *) object;

	return rv;
}

static int
__pkcs15_create_prkey_object(struct pkcs15_fw_data *fw_data,
	struct sc_pkcs15_object *prkey, struct pkcs15_any_object **prkey_object)
{
	struct pkcs15_prkey_object *object;
	int rv;

	rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &object,
					prkey, &pkcs15_prkey_ops,
					sizeof(struct pkcs15_prkey_object));
	if (rv >= 0)
		object->prv_info = (struct sc_pkcs15_prkey_info *) prkey->data;

	if (prkey_object != NULL)
		*prkey_object = (struct pkcs15_any_object *) object;

	return 0;
}

static int
pkcs15_create_pkcs11_objects(struct pkcs15_fw_data *fw_data,
			     int p15_type, const char *name,
			     int (*create)(struct pkcs15_fw_data *,
				     	   struct sc_pkcs15_object *,
				     	   struct pkcs15_any_object **any_object))
{
	struct sc_pkcs15_object *p15_object[MAX_OBJECTS];
	int i, count, rv;

        rv = count = sc_pkcs15_get_objects(fw_data->p15_card, p15_type, p15_object, MAX_OBJECTS);

	if (rv >= 0) {
		sc_debug(context, "Found %d %s%s\n", count,
				name, (count == 1)? "" : "s");
	}

	for (i = 0; rv >= 0 && i < count; i++) {
		rv = create(fw_data, p15_object[i], NULL);
	}

	return count;
}

static void
__pkcs15_prkey_bind_related(struct pkcs15_fw_data *fw_data, struct pkcs15_prkey_object *pk)
{
	sc_pkcs15_id_t *id = &pk->prv_info->id;
	unsigned int i;

	for (i = 0; i < fw_data->num_objects; i++) {
		struct pkcs15_any_object *obj = fw_data->objects[i];

		if (obj->base.flags & SC_PKCS11_OBJECT_HIDDEN)
			continue;
		if (is_privkey(obj) && obj != (struct pkcs15_any_object *) pk) {
			/* merge private keys with the same ID and
			 * different usage bits */
			struct pkcs15_prkey_object *other, **pp;

			other = (struct pkcs15_prkey_object *) obj;
			if (sc_pkcs15_compare_id(&other->prv_info->id, id)) {
				obj->base.flags |= SC_PKCS11_OBJECT_HIDDEN;
				for (pp = &pk->prv_next; *pp; pp = &(*pp)->prv_next)
					;
				*pp = (struct pkcs15_prkey_object *) obj;
			}
		} else
		if (is_cert(obj) && !pk->prv_cert) {
			struct pkcs15_cert_object *cert;
			
			cert = (struct pkcs15_cert_object *) obj;
			if (sc_pkcs15_compare_id(&cert->cert_info->id, id))
				pk->prv_cert = cert;
		} else
		if (is_pubkey(obj) && !pk->prv_pubkey) {
			struct pkcs15_pubkey_object *pubkey;
			
			pubkey = (struct pkcs15_pubkey_object *) obj;
			if (sc_pkcs15_compare_id(&pubkey->pub_info->id, id))
				pk->prv_pubkey = pubkey;
		}
	}
}

static void
__pkcs15_cert_bind_related(struct pkcs15_fw_data *fw_data, struct pkcs15_cert_object *cert)
{
	struct sc_pkcs15_cert *c1 = cert->cert_data, *c2;
	unsigned int i;

	/* Loop over all certificates see if we find the certificate of
	 * the issuer */
	for (i = 0; i < fw_data->num_objects; i++) {
		struct pkcs15_any_object *obj = fw_data->objects[i];

		if (!is_cert(obj) || obj == (struct pkcs15_any_object *) cert)
			continue;

		c2 = ((struct pkcs15_cert_object *) obj)->cert_data;

		if (!c1 || !c2 || !c1->issuer_len || !c2->subject_len)
			continue;
		if (c1->issuer_len == c2->subject_len
		 && !memcmp(c1->issuer, c2->subject, c1->issuer_len)) {
			cert->cert_issuer = (struct pkcs15_cert_object *) obj;
			return;
		}
	}
}

static void
pkcs15_bind_related_objects(struct pkcs15_fw_data *fw_data)
{
	unsigned int i;

	/* Loop over all private keys and attached related certificate
	 * and/or public key
	 */
	for (i = 0; i < fw_data->num_objects; i++) {
		struct pkcs15_any_object *obj = fw_data->objects[i];

		if (obj->base.flags & SC_PKCS11_OBJECT_HIDDEN)
			continue;
		if (is_privkey(obj)) {
			__pkcs15_prkey_bind_related(fw_data, (struct pkcs15_prkey_object *) obj);
		} else if (is_cert(obj)) {
			__pkcs15_cert_bind_related(fw_data, (struct pkcs15_cert_object *) obj);
		}
	}
}

static int
pool_is_present(struct sc_pkcs11_pool *pool, struct pkcs15_any_object *obj)
{
	struct sc_pkcs11_pool_item *item;

	for (item = pool->head; item != NULL; item = item->next) {
		if (obj == (struct pkcs15_any_object *) item->item)
			return 1;
	}

	return 0;
}

static void
pkcs15_add_object(struct sc_pkcs11_slot *slot,
		  struct pkcs15_any_object *obj,
		  CK_OBJECT_HANDLE_PTR pHandle)
{
	if (obj == NULL
	 || (obj->base.flags & (SC_PKCS11_OBJECT_HIDDEN | SC_PKCS11_OBJECT_RECURS)))
		return;

	if (pool_is_present(&slot->object_pool, obj))
		return;

	pool_insert(&slot->object_pool, obj, pHandle);
	obj->base.flags |= SC_PKCS11_OBJECT_SEEN;
	obj->refcount++;

	/* Add related objects
	 * XXX prevent infinite recursion when a card specifies two certificates
	 * referring to each other.
	 */
	obj->base.flags |= SC_PKCS11_OBJECT_RECURS;

	switch (__p15_type(obj)) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
		if (obj->related_cert == NULL)
			pkcs15_add_object(slot, (struct pkcs15_any_object *) obj->related_pubkey, NULL);
		pkcs15_add_object(slot, (struct pkcs15_any_object *) obj->related_cert, NULL);
		break;
	case SC_PKCS15_TYPE_CERT_X509:
		pkcs15_add_object(slot, (struct pkcs15_any_object *) obj->related_pubkey, NULL);
		pkcs15_add_object(slot, (struct pkcs15_any_object *) obj->related_cert, NULL);
		break;
	}

	obj->base.flags &= ~SC_PKCS11_OBJECT_RECURS;
}

static void pkcs15_init_slot(struct sc_pkcs15_card *card,
		struct sc_pkcs11_slot *slot,
		struct sc_pkcs15_object *auth)
{
	struct pkcs15_slot_data *fw_data;
	struct sc_pkcs15_pin_info *pin_info = NULL;
	char tmp[64];

	pkcs15_init_token_info(card, &slot->token_info);
	slot->token_info.flags |= CKF_USER_PIN_INITIALIZED
				| CKF_TOKEN_INITIALIZED;
	if (card->card->slot->capabilities & SC_SLOT_CAP_PIN_PAD) {
		slot->token_info.flags |= CKF_PROTECTED_AUTHENTICATION_PATH;
		sc_pkcs11_conf.cache_pins = 0;
	}
	if (card->card->caps & SC_CARD_CAP_RNG)
		slot->token_info.flags |= CKF_RNG;
	slot->fw_data = fw_data = (struct pkcs15_slot_data *) calloc(1, sizeof(*fw_data));
	fw_data->auth_obj = auth;

	if (auth != NULL) {
		pin_info = (struct sc_pkcs15_pin_info*) auth->data;

		if (auth->label[0]) {
			snprintf(tmp, sizeof(tmp), "%s (%s)",
				card->label, auth->label);
		} else {
			snprintf(tmp, sizeof(tmp), "%s", card->label);
		}
		slot->token_info.flags |= CKF_LOGIN_REQUIRED;
	} else
		sprintf(tmp, card->label);
	strcpy_bp(slot->token_info.label, tmp, 32);

	if (pin_info && pin_info->magic == SC_PKCS15_PIN_MAGIC) {
		slot->token_info.ulMaxPinLen = pin_info->max_length;
		slot->token_info.ulMinPinLen = pin_info->min_length;
	} else {
		/* choose reasonable defaults */
		slot->token_info.ulMaxPinLen = 8;
		slot->token_info.ulMinPinLen = 4;
	}

	sc_debug(context, "Initialized token '%s'\n", tmp);
}

static CK_RV pkcs15_create_slot(struct sc_pkcs11_card *p11card,
		struct sc_pkcs15_object *auth,
		struct sc_pkcs11_slot **out)
{
        struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	struct sc_pkcs11_slot *slot;
	int rv;

	rv = slot_allocate(&slot, p11card);
	if (rv != CKR_OK)
		return rv;

	/* There's a token in this slot */
	slot->slot_info.flags |= CKF_TOKEN_PRESENT;

	/* Fill in the slot/token info from pkcs15 data */
	pkcs15_init_slot(fw_data->p15_card, slot, auth);

	*out = slot;
	return CKR_OK;
}

static CK_RV pkcs15_create_tokens(struct sc_pkcs11_card *p11card)
{
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	struct sc_pkcs15_object *auths[MAX_OBJECTS];
	struct sc_pkcs11_slot *slot;
	int i, rv, reader = p11card->reader;
        int auth_count;
	unsigned int j;

        rv = sc_pkcs15_get_objects(fw_data->p15_card,
					SC_PKCS15_TYPE_AUTH_PIN,
					auths,
					SC_PKCS15_MAX_PINS);
	if (rv < 0)
                return sc_to_cryptoki_error(rv, reader);
	sc_debug(context, "Found %d authentication objects\n", rv);
	auth_count = rv;

        rv = pkcs15_create_pkcs11_objects(fw_data,
				SC_PKCS15_TYPE_PRKEY_RSA,
				"private key",
				__pkcs15_create_prkey_object);
 	if (rv < 0)
                return sc_to_cryptoki_error(rv, reader);

        rv = pkcs15_create_pkcs11_objects(fw_data,
				SC_PKCS15_TYPE_PUBKEY_RSA,
				"public key",
				__pkcs15_create_pubkey_object);
 	if (rv < 0)
                return sc_to_cryptoki_error(rv, reader);

	rv = pkcs15_create_pkcs11_objects(fw_data,
				SC_PKCS15_TYPE_CERT_X509,
				"certificate",
				__pkcs15_create_cert_object);
	if (rv < 0)
                return sc_to_cryptoki_error(rv, reader);

	/* Match up related keys and certificates */
	pkcs15_bind_related_objects(fw_data);

	for (i = 0; i < auth_count; i++) {
		struct sc_pkcs15_pin_info *pin_info = NULL;

		pin_info = (struct sc_pkcs15_pin_info*) auths[i]->data;

		/* Ignore any non-authentication PINs */
		if ((pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN)
		 || (pin_info->flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN))
			continue;

		/* Add all the private keys related to this pin */
		rv = pkcs15_create_slot(p11card, auths[i], &slot);
		if (rv != CKR_OK)
			return rv;
		for (j=0; j < fw_data->num_objects; j++) {
			struct pkcs15_any_object *obj = fw_data->objects[j];

			if (!is_privkey(obj)
			 || !sc_pkcs15_compare_id(&pin_info->auth_id,
						  &obj->p15_object->auth_id))
				continue;

			sc_debug(context, "Adding private key %d to PIN %d\n", j, i);
			pkcs15_add_object(slot, obj, NULL);
		}
	}

	/* Add all public objects to a virtual slot without pin protection */
	slot = NULL;

	/* Add all the remaining objects */
	for (j = 0; j < fw_data->num_objects; j++) {
		struct pkcs15_any_object *obj = fw_data->objects[j];

		if (!(obj->base.flags & SC_PKCS11_OBJECT_SEEN)) {
                        sc_debug(context, "Object %d was not seen previously\n", j);
			if (!slot) {
				rv = pkcs15_create_slot(p11card, NULL, &slot);
				if (rv != CKR_OK)
					return rv;
			}
			pkcs15_add_object(slot, obj, NULL);
		}
	}

	/* Create read/write slots */
	while (slot_allocate(&slot, p11card) == CKR_OK) {
		if (!sc_pkcs11_conf.hide_empty_tokens) {
			slot->slot_info.flags |= CKF_TOKEN_PRESENT;
			pkcs15_init_token_info(fw_data->p15_card, &slot->token_info);
			strcpy_bp(slot->token_info.label, fw_data->p15_card->label, 32);
			slot->token_info.flags |= CKF_TOKEN_INITIALIZED;
		}
	}

	sc_debug(context, "All tokens created\n");
	return CKR_OK;
}

static CK_RV pkcs15_release_token(struct sc_pkcs11_card *p11card, void *fw_token)
{
	unlock_card((struct pkcs15_fw_data *) p11card->fw_data);
        return CKR_OK;
}

static CK_RV pkcs15_login(struct sc_pkcs11_card *p11card,
			  void *fw_token,
			  CK_USER_TYPE userType,
			  CK_CHAR_PTR pPin,
			  CK_ULONG ulPinLen)
{
	int rc;
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	struct sc_pkcs15_card *card = fw_data->p15_card;
        struct sc_pkcs15_object *auth_object;
	struct sc_pkcs15_pin_info *pin;

	switch (userType) {
	case CKU_USER:
		auth_object = slot_data_auth(fw_token);
		if (auth_object == NULL)
			return CKR_USER_PIN_NOT_INITIALIZED;
		break;
	case CKU_SO:
		/* A card with no SO PIN is treated as if no SO login
		 * is required */
		rc = sc_pkcs15_find_so_pin(card, &auth_object);

		/* If there's no SO PIN on the card, silently
		 * accept any PIN, and lock the card if required */
		if (rc == SC_ERROR_OBJECT_NOT_FOUND
		 && sc_pkcs11_conf.lock_login)
			rc = lock_card(fw_data);
		if (rc < 0)
			return sc_to_cryptoki_error(rc, p11card->reader);
		break;
	default:
		return CKR_USER_TYPE_INVALID;
	}
	pin = (struct sc_pkcs15_pin_info *) auth_object->data;

	if (p11card->card->slot->capabilities & SC_SLOT_CAP_PIN_PAD) {
		/* pPin should be NULL in case of a pin pad reader, but
		 * some apps (e.g. older Netscapes) don't know about it.
		 * So we don't require that pPin == NULL, but set it to
		 * NULL ourselves. This way, you can supply an empty (if
		 * possible) or fake PIN if an application asks a PIN).
		 */
		pPin = NULL;
		ulPinLen = 0;
	} else
	if (ulPinLen < pin->min_length ||
	    ulPinLen > pin->max_length)
		return CKR_ARGUMENTS_BAD;

	/* By default, we make the pcsc daemon keep other processes
	 * from accessing the card while we're logged in. Otherwise
	 * an attacker could perform some crypto operation after
	 * we've authenticated with the card */
	if (sc_pkcs11_conf.lock_login && (rc = lock_card(fw_data)) < 0)
		return sc_to_cryptoki_error(rc, p11card->reader);

	rc = sc_pkcs15_verify_pin(card, pin, pPin, ulPinLen);
        sc_debug(context, "PIN verification returned %d\n", rc);
	
	if (rc >= 0)
		cache_pin(fw_token, userType, pPin, ulPinLen);

	return sc_to_cryptoki_error(rc, p11card->reader);
}

static CK_RV pkcs15_logout(struct sc_pkcs11_card *p11card, void *fw_token)
{
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	int rc = 0;

	cache_pin(fw_token, CKU_SO, NULL, 0);
	cache_pin(fw_token, CKU_USER, NULL, 0);

	sc_logout(fw_data->p15_card->card);

	if (sc_pkcs11_conf.lock_login)
		rc = unlock_card(fw_data);
	return sc_to_cryptoki_error(rc, p11card->reader);
}

static CK_RV pkcs15_change_pin(struct sc_pkcs11_card *p11card,
			  void *fw_token,
			  CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen,
			  CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	int rc;
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	struct sc_pkcs15_pin_info *pin;

	if (!(pin = slot_data_pin_info(fw_token)))
		return CKR_USER_PIN_NOT_INITIALIZED;

	if (p11card->card->slot->capabilities & SC_SLOT_CAP_PIN_PAD) {
		/* pPin should be NULL in case of a pin pad reader, but
		 * some apps (e.g. older Netscapes) don't know about it.
		 * So we don't require that pPin == NULL, but set it to
		 * NULL ourselves. This way, you can supply an empty (if
		 * possible) or fake PIN if an application asks a PIN).
		 */
		pOldPin = pNewPin = NULL;
		ulOldLen = ulNewLen = 0;
	} else
	if (ulNewLen < pin->min_length ||
	    ulNewLen > pin->max_length)
		return CKR_PIN_LEN_RANGE;

	rc = sc_pkcs15_change_pin(fw_data->p15_card, pin, pOldPin, ulOldLen,
				pNewPin, ulNewLen);
        sc_debug(context, "PIN verification returned %d\n", rc);

	if (rc >= 0)
		cache_pin(fw_token, CKU_USER, pNewPin, ulNewLen);
	return sc_to_cryptoki_error(rc, p11card->reader);
}

#ifdef USE_PKCS15_INIT
static CK_RV pkcs15_init_pin(struct sc_pkcs11_card *p11card,
			struct sc_pkcs11_slot *slot,
			CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	struct sc_pkcs15init_pinargs args;
	struct sc_profile	*profile;
	struct sc_pkcs15_object	*auth_obj;
	int			rc;

	rc = sc_pkcs15init_bind(p11card->card, "pkcs15", NULL, &profile);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, p11card->reader);

	memset(&args, 0, sizeof(args));
	args.label = "User PIN";
	args.pin = pPin;
	args.pin_len = ulPinLen;
	rc = sc_pkcs15init_store_pin(fw_data->p15_card, profile, &args);

	sc_pkcs15init_unbind(profile);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, p11card->reader);

	rc = sc_pkcs15_find_pin_by_auth_id(fw_data->p15_card, &args.auth_id, &auth_obj);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, p11card->reader);

	/* Re-initialize the slot */
	free(slot->fw_data);
	pkcs15_init_slot(fw_data->p15_card, slot, auth_obj);

	cache_pin(slot->fw_data, CKU_USER, pPin, ulPinLen);

	return CKR_OK;
}

static CK_RV pkcs15_create_private_key(struct sc_pkcs11_card *p11card,
		struct sc_pkcs11_slot *slot,
		struct sc_profile *profile,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject)
{
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	struct sc_pkcs15init_prkeyargs args;
	struct pkcs15_any_object *key_any_obj;
	struct sc_pkcs15_object	*key_obj;
	struct sc_pkcs15_pin_info *pin;
	CK_KEY_TYPE		key_type;
	struct sc_pkcs15_prkey_rsa *rsa;
	int			rc, rv;

	memset(&args, 0, sizeof(args));

	/* See if the "slot" is pin protected. If so, get the
	 * PIN id */
	if ((pin = slot_data_pin_info(slot->fw_data)) != NULL)
		args.auth_id = pin->auth_id;

	/* Get the key type */
	rv = attr_find(pTemplate, ulCount, CKA_KEY_TYPE, &key_type, NULL);
	if (rv != CKR_OK)
		return rv;
	if (key_type != CKK_RSA)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	args.key.algorithm = SC_ALGORITHM_RSA;
	rsa = &args.key.u.rsa;

	rv = CKR_OK;
	while (ulCount--) {
		CK_ATTRIBUTE_PTR attr = pTemplate++;
		sc_pkcs15_bignum_t *bn = NULL;

		switch (attr->type) {
		/* Skip attrs we already know or don't care for */
		case CKA_CLASS:
		case CKA_KEY_TYPE:
		case CKA_MODULUS_BITS:
		case CKA_PRIVATE:
		       	break;
		case CKA_LABEL:
			args.label = (char *) attr->pValue;
			break;
		case CKA_ID:
			args.id.len = sizeof(args.id.value);
			rv = attr_extract(attr, args.id.value, &args.id.len);
			if (rv != CKR_OK)
				goto out;
			break;
		case CKA_MODULUS:
			bn = &rsa->modulus; break;
		case CKA_PUBLIC_EXPONENT:
			bn = &rsa->exponent; break;
		case CKA_PRIVATE_EXPONENT:
			bn = &rsa->d; break;
		case CKA_PRIME_1:
			bn = &rsa->p; break;
		case CKA_PRIME_2:
			bn = &rsa->q; break;
		default:
			/* ignore unknown attrs, or flag error? */
			continue;
		}

		if (bn) {
			if (attr->ulValueLen > 1024)
				return CKR_ATTRIBUTE_VALUE_INVALID;
			bn->len = attr->ulValueLen;
			bn->data = (u8 *) attr->pValue;
		}
	}

	if (!rsa->modulus.len || !rsa->exponent.len || !rsa->d.len
	 || !rsa->p.len || !rsa->q.len) {
		rv = CKR_TEMPLATE_INCOMPLETE;
		goto out;
	}

	rc = sc_pkcs15init_store_private_key(fw_data->p15_card, profile, &args, &key_obj);
	if (rc < 0) {
		rv = sc_to_cryptoki_error(rc, p11card->reader);
		goto out;
	}

	/* Create a new pkcs11 object for it */
	__pkcs15_create_prkey_object(fw_data, key_obj, &key_any_obj);
	pkcs15_add_object(slot, key_any_obj, phObject);

	rv = CKR_OK;

out:	return rv;
}

static CK_RV pkcs15_create_public_key(struct sc_pkcs11_card *p11card,
		struct sc_pkcs11_slot *slot,
		struct sc_profile *profile,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject)
{
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	struct sc_pkcs15init_pubkeyargs args;
	struct pkcs15_any_object *key_any_obj;
	struct sc_pkcs15_object	*key_obj;
	struct sc_pkcs15_pin_info *pin;
	CK_KEY_TYPE		key_type;
	struct sc_pkcs15_pubkey_rsa *rsa;
	int			rc, rv;

	memset(&args, 0, sizeof(args));

	/* See if the "slot" is pin protected. If so, get the
	 * PIN id */
	if ((pin = slot_data_pin_info(slot->fw_data)) != NULL)
		args.auth_id = pin->auth_id;

	/* Get the key type */
	rv = attr_find(pTemplate, ulCount, CKA_KEY_TYPE, &key_type, NULL);
	if (rv != CKR_OK)
		return rv;
	if (key_type != CKK_RSA)
		return CKR_ATTRIBUTE_VALUE_INVALID;
	args.key.algorithm = SC_ALGORITHM_RSA;
	rsa = &args.key.u.rsa;

	rv = CKR_OK;
	while (ulCount--) {
		CK_ATTRIBUTE_PTR attr = pTemplate++;
		sc_pkcs15_bignum_t *bn = NULL;

		switch (attr->type) {
		/* Skip attrs we already know or don't care for */
		case CKA_CLASS:
		case CKA_KEY_TYPE:
		case CKA_MODULUS_BITS:
		case CKA_PRIVATE:
		       	break;
		case CKA_LABEL:
			args.label = (char *) attr->pValue;
			break;
		case CKA_ID:
			args.id.len = sizeof(args.id.value);
			rv = attr_extract(attr, args.id.value, &args.id.len);
			if (rv != CKR_OK)
				goto out;
			break;
		case CKA_MODULUS:
			bn = &rsa->modulus; break;
		case CKA_PUBLIC_EXPONENT:
			bn = &rsa->exponent; break;
		default:
			/* ignore unknown attrs, or flag error? */
			continue;
		}

		if (bn) {
			if (attr->ulValueLen > 1024)
				return CKR_ATTRIBUTE_VALUE_INVALID;
			bn->len = attr->ulValueLen;
			bn->data = (u8 *) attr->pValue;
		}
	}

	if (!rsa->modulus.len || !rsa->exponent.len) {
		rv = CKR_TEMPLATE_INCOMPLETE;
		goto out;
	}

	rc = sc_pkcs15init_store_public_key(fw_data->p15_card, profile, &args, &key_obj);
	if (rc < 0) {
		rv = sc_to_cryptoki_error(rc, p11card->reader);
		goto out;
	}

	/* Create a new pkcs11 object for it */
	__pkcs15_create_pubkey_object(fw_data, key_obj, &key_any_obj);
	pkcs15_add_object(slot, key_any_obj, phObject);

	rv = CKR_OK;

out:	return rv;
}

static CK_RV pkcs15_create_certificate(struct sc_pkcs11_card *p11card,
		struct sc_pkcs11_slot *slot,
		struct sc_profile *profile,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject)
{
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	struct sc_pkcs15init_certargs args;
	struct pkcs15_any_object *cert_any_obj;
	struct sc_pkcs15_object	*cert_obj;
	CK_CERTIFICATE_TYPE	cert_type;
	CK_BBOOL		bValue;
	int			rc, rv;

	memset(&args, 0, sizeof(args));

	/* Get the key type */
	rv = attr_find(pTemplate, ulCount, CKA_CERTIFICATE_TYPE,
				&cert_type, NULL);
	if (rv != CKR_OK)
		return rv;
	if (cert_type != CKC_X_509)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	rv = CKR_OK;
	while (ulCount--) {
		CK_ATTRIBUTE_PTR attr = pTemplate++;

		switch (attr->type) {
		/* Skip attrs we already know or don't care for */
		case CKA_CLASS:
		       	break;
		case CKA_PRIVATE:
			rv = attr_extract(attr, &bValue, NULL);
			if (bValue) {
				rv = CKR_TEMPLATE_INCONSISTENT;
				goto out;
			}
			break;
		case CKA_LABEL:
			args.label = (char *) attr->pValue;
			break;
		case CKA_ID:
			args.id.len = sizeof(args.id.value);
			rv = attr_extract(attr, args.id.value, &args.id.len);
			if (rv != CKR_OK)
				goto out;
			break;
		case CKA_VALUE:
			args.der_encoded.len = attr->ulValueLen;
			args.der_encoded.value = (u8 *) attr->pValue;
			break;
		default:
			/* ignore unknown attrs, or flag error? */
			continue;
		}
	}

	if (args.der_encoded.len == 0) {
		rv = CKR_TEMPLATE_INCOMPLETE;
		goto out;
	}

	rc = sc_pkcs15init_store_certificate(fw_data->p15_card, profile, &args, &cert_obj);
	if (rc < 0) {
		rv = sc_to_cryptoki_error(rc, p11card->reader);
		goto out;
	}
	/* Create a new pkcs11 object for it */
	__pkcs15_create_cert_object(fw_data, cert_obj, &cert_any_obj);
	pkcs15_add_object(slot, cert_any_obj, phObject);

	rv = CKR_OK;

out:	return rv;
}

static CK_RV pkcs15_create_object(struct sc_pkcs11_card *p11card,
		struct sc_pkcs11_slot *slot,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject)
{
	struct sc_profile *profile = NULL;
	struct pkcs15_slot_data *data;
	CK_OBJECT_CLASS	_class;
	int		rv, rc;

	rv = attr_find(pTemplate, ulCount, CKA_CLASS, &_class, NULL);
	if (rv != CKR_OK)
		return rv;

	/* Bind the profile */
	rc = sc_pkcs15init_bind(p11card->card, "pkcs15", NULL, &profile);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, p11card->reader);

	rc = sc_lock(p11card->card);
	if (rc < 0) {
		sc_pkcs15init_unbind(profile);
		return sc_to_cryptoki_error(rc, p11card->reader);
	}

	/* Add the PINs the user presented so far. Some initialization
	 * routines need to present these PINs again because some
	 * card operations may clobber the authentication state
	 * (the GPK for instance) */
	data = slot_data(slot->fw_data);
	if (data->pin[CKU_SO].len)
		sc_pkcs15init_set_pin_data(profile, SC_PKCS15INIT_SO_PIN,
			data->pin[CKU_SO].value, data->pin[CKU_SO].len);
	if (data->pin[CKU_USER].len)
		sc_pkcs15init_set_pin_data(profile, SC_PKCS15INIT_USER_PIN,
			data->pin[CKU_USER].value, data->pin[CKU_USER].len);

	switch (_class) {
	case CKO_PRIVATE_KEY:
		rv = pkcs15_create_private_key(p11card, slot, profile,
				pTemplate, ulCount, phObject);
		break;
	case CKO_PUBLIC_KEY:
		rv = pkcs15_create_public_key(p11card, slot, profile,
				pTemplate, ulCount, phObject);
		break;
	case CKO_CERTIFICATE:
		rv = pkcs15_create_certificate(p11card, slot, profile,
				pTemplate, ulCount, phObject);
		break;
	default:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}

	sc_unlock(p11card->card);
	sc_pkcs15init_unbind(profile);
	return rv;
}

static CK_RV
get_X509_usage_privk(CK_ATTRIBUTE_PTR pTempl, CK_ULONG ulCount, unsigned long *x509_usage)
{
	CK_ULONG i;
	for (i = 0; i < ulCount; i++) {
		CK_ATTRIBUTE_TYPE typ = pTempl[i].type;
		CK_BBOOL *val = (CK_BBOOL *) pTempl[i].pValue;
		if (val == NULL)
			continue;
		if (typ == CKA_SIGN && *val)
			*x509_usage |= 1;
		if (typ == CKA_UNWRAP && *val)
			*x509_usage |= 4;
		if (typ == CKA_DECRYPT && *val)
			*x509_usage |= 8;
		if (typ == CKA_DERIVE && *val)
			*x509_usage |= 16;
		if (typ == CKA_VERIFY || typ == CKA_WRAP || typ == CKA_ENCRYPT) {
			sc_debug(context, "get_X509_usage_privk(): invalid typ = 0x%0x\n", typ);
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}
	return CKR_OK;
}

static CK_RV
get_X509_usage_pubk(CK_ATTRIBUTE_PTR pTempl, CK_ULONG ulCount, unsigned long *x509_usage)
{
	CK_ULONG i;
	for (i = 0; i < ulCount; i++) {
		CK_ATTRIBUTE_TYPE typ = pTempl[i].type;
		CK_BBOOL *val = (CK_BBOOL *) pTempl[i].pValue;
		if (val == NULL)
			continue;
		if (typ == CKA_VERIFY && *val)
			*x509_usage |= 1;
		if (typ == CKA_WRAP && *val)
			*x509_usage |= 4;
		if (typ == CKA_ENCRYPT && *val)
			*x509_usage |= 8;
		if (typ == CKA_DERIVE && *val)
			*x509_usage |= 16;
		if (typ == CKA_SIGN || typ == CKA_UNWRAP || typ == CKA_DECRYPT) {
			sc_debug(context, "get_X509_usage_pubk(): invalid typ = 0x%0x\n", typ);
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}
	return CKR_OK;
}

/* FIXME: check for the public exponent in public key template and use this value */
CK_RV pkcs15_gen_keypair(struct sc_pkcs11_card *p11card, struct sc_pkcs11_slot *slot,
			CK_MECHANISM_PTR pMechanism,
			CK_ATTRIBUTE_PTR pPubTpl, CK_ULONG ulPubCnt,
			CK_ATTRIBUTE_PTR pPrivTpl, CK_ULONG ulPrivCnt,
			CK_OBJECT_HANDLE_PTR phPubKey, CK_OBJECT_HANDLE_PTR phPrivKey)                /* gets priv. key handle */
{
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_pin_info *pin;
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	struct pkcs15_slot_data *p15_data = slot_data(slot->fw_data);
	struct sc_pkcs15_card *p15card = fw_data->p15_card;
	struct sc_pkcs15init_prkeyargs	priv_args;
	struct sc_pkcs15init_pubkeyargs pub_args;
	struct sc_pkcs15_object	 *priv_key_obj;
	struct sc_pkcs15_object	 *pub_key_obj;
	struct pkcs15_any_object *priv_any_obj;
	struct pkcs15_any_object *pub_any_obj;
	struct sc_pkcs15_id id;
	size_t		len;
	CK_KEY_TYPE	keytype = CKK_RSA;
	CK_ULONG	keybits;
	char		pub_label[SC_PKCS15_MAX_LABEL_SIZE];
	char		priv_label[SC_PKCS15_MAX_LABEL_SIZE];
	int rc, rv = CKR_OK;

	sc_debug(context, "Keypair generation, mech = 0x%0x\n", pMechanism->mechanism);

	if (pMechanism->mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN)
		return CKR_MECHANISM_INVALID;

	rc = sc_pkcs15init_bind(p11card->card, "pkcs15", NULL, &profile);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, p11card->reader);

	memset(&priv_args, 0, sizeof(priv_args));
	memset(&pub_args, 0, sizeof(pub_args));

	rc = sc_lock(p11card->card);
	if (rc < 0) {
		sc_pkcs15init_unbind(profile);
		return sc_to_cryptoki_error(rc, p11card->reader);
	}

	/* 1. Convert the pkcs11 attributes to pkcs15init args */

	if ((pin = slot_data_pin_info(slot->fw_data)) != NULL)
		priv_args.auth_id = pub_args.auth_id = pin->auth_id;

	rv = attr_find2(pPubTpl, ulPubCnt, pPrivTpl, ulPrivCnt, CKA_KEY_TYPE,
		&keytype, NULL);
	if (rv == CKR_OK && keytype != CKK_RSA) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto kpgen_done;
	}
	priv_args.key.algorithm = pub_args.key.algorithm = SC_ALGORITHM_RSA;

	rv = attr_find2(pPubTpl, ulPubCnt, pPrivTpl, ulPrivCnt,	CKA_MODULUS_BITS,
		&keybits, NULL);
	if (rv != CKR_OK)
			keybits = 1024; /* Default key size */
	/* To do: check allowed values of keybits */

	id.len = SC_PKCS15_MAX_ID_SIZE;
	rv = attr_find2(pPubTpl, ulPubCnt, pPrivTpl, ulPrivCnt,	CKA_ID,
		&id.value, &id.len);
	if (rv == CKR_OK)
		priv_args.id = pub_args.id = id;

	len = sizeof(priv_label);
	rv = attr_find(pPrivTpl, ulPrivCnt, CKA_LABEL, priv_label, &len);
	if (rv == CKR_OK) {
		priv_label[SC_PKCS15_MAX_LABEL_SIZE - 1] = '\0';
		priv_args.label = priv_label;
	}
	len = sizeof(pub_label);
	rv = attr_find(pPubTpl, ulPubCnt, CKA_LABEL, pub_label, &len);
	if (rv == CKR_OK) {
		pub_label[SC_PKCS15_MAX_LABEL_SIZE - 1] = '\0';
		pub_args.label = pub_label;
	}

	rv = get_X509_usage_privk(pPrivTpl, ulPrivCnt, &priv_args.x509_usage);
	if (rv == CKR_OK)
		rv = get_X509_usage_pubk(pPubTpl, ulPubCnt, &priv_args.x509_usage);
	if (rv != CKR_OK)
		goto kpgen_done;
	pub_args.x509_usage = priv_args.x509_usage;

	/* 2. Add the PINs the user presented so far. Some initialization
	 * routines need to present these PINs again because some
	 * card operations may clobber the authentication state
	 * (the GPK for instance) */

	if (p15_data->pin[CKU_SO].len)
		sc_pkcs15init_set_pin_data(profile, SC_PKCS15INIT_SO_PIN,
			p15_data->pin[CKU_SO].value, p15_data->pin[CKU_SO].len);
	if (p15_data->pin[CKU_USER].len)
		sc_pkcs15init_set_pin_data(profile, SC_PKCS15INIT_USER_PIN,
			p15_data->pin[CKU_USER].value, p15_data->pin[CKU_USER].len);

	/* 3.a Try on-card key pair generation */

	rc = sc_pkcs15init_generate_key(fw_data->p15_card, profile,
		&priv_args, keybits, &priv_key_obj);
	if (rc >= 0) {
		id = ((struct sc_pkcs15_prkey_info *) priv_key_obj->data)->id;
		rc = sc_pkcs15_find_pubkey_by_id(fw_data->p15_card, &id, &pub_key_obj);
		if (rc != 0) {
			sc_debug(context, "sc_pkcs15_find_pubkey_by_id returned %d\n", rc);
			rv = sc_to_cryptoki_error(rc, p11card->reader);
			goto kpgen_done;
		}
	}
	else if (rc != SC_ERROR_NOT_SUPPORTED) {
		sc_debug(context, "sc_pkcs15init_generate_key returned %d\n", rc);
		rv = sc_to_cryptoki_error(rc, p11card->reader);
		goto kpgen_done;
	}
	else {
		/* 3.b Try key pair generation in software, if allowed */
		
		if (!sc_pkcs11_conf.soft_keygen_allowed) {
			sc_debug(context, "On card keypair gen not supported, software keypair gen not allowed");
			rv = CKR_FUNCTION_FAILED;
			goto kpgen_done;
		}

		sc_debug(context, "Doing key pair generation in software\n");
		rv = sc_pkcs11_gen_keypair_soft(keytype, keybits,
			&priv_args.key, &pub_args.key);
		if (rv != CKR_OK) {
			sc_debug(context, "sc_pkcs11_gen_keypair_soft failed: 0x%0x\n", rv);
			goto kpgen_done;
		}

		/* Write the new public and private keys to the pkcs15 files */
		rc = sc_pkcs15init_store_private_key(p15card, profile,
			&priv_args, &priv_key_obj);
		if (rc >= 0)
			rc = sc_pkcs15init_store_public_key(p15card, profile,
				&pub_args, &pub_key_obj);
		if (rc < 0) {
			sc_debug(context, "private/public keys not stored: %d\n", rc);
			rv = sc_to_cryptoki_error(rc, p11card->reader);
			goto kpgen_done;
		}
	}

	/* 4. Create new pkcs11 public and private key object */

	rc = __pkcs15_create_prkey_object(fw_data, priv_key_obj, &priv_any_obj);
	if (rc == 0)
		__pkcs15_create_pubkey_object(fw_data, pub_key_obj, &pub_any_obj);
	if (rc != 0) {
		sc_debug(context, "__pkcs15_create_pr/pubkey_object returned %d\n", rc);
		rv = sc_to_cryptoki_error(rc, p11card->reader);
		goto kpgen_done;
	}
	pkcs15_add_object(slot, priv_any_obj, phPrivKey);
	pkcs15_add_object(slot, pub_any_obj, phPubKey);

kpgen_done:
	sc_unlock(p11card->card);
	sc_pkcs15init_unbind(profile);

	return rv;
}
#endif

struct sc_pkcs11_framework_ops framework_pkcs15 = {
	pkcs15_bind,
	pkcs15_unbind,
	pkcs15_create_tokens,
	pkcs15_release_token,
	pkcs15_login,
        pkcs15_logout,
	pkcs15_change_pin,
        NULL,			/* init_token */
#ifdef USE_PKCS15_INIT
	pkcs15_init_pin,
        pkcs15_create_object,
        pkcs15_gen_keypair,
#else
        NULL,
        NULL
#endif
};

CK_RV pkcs15_set_attrib(struct sc_pkcs11_session *session,
                               struct sc_pkcs15_object *p15_object,
                               CK_ATTRIBUTE_PTR attr)
{
#ifndef USE_PKCS15_INIT
       return CKR_FUNCTION_NOT_SUPPORTED;
#else
       struct sc_profile *profile = NULL;
       struct sc_pkcs11_card *p11card = session->slot->card;
       struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
       struct pkcs15_slot_data *p15_data = slot_data(session->slot->fw_data);
       struct sc_pkcs15_id id;
       int rc = 0;
       CK_RV rv = CKR_OK;

       rc = sc_pkcs15init_bind(p11card->card, "pkcs15", NULL, &profile);
       if (rc < 0)
               return sc_to_cryptoki_error(rc, p11card->reader);

	rc = sc_lock(p11card->card);
	if (rc < 0) {
		sc_pkcs15init_unbind(profile);
		return sc_to_cryptoki_error(rc, p11card->reader);
	}

       /* 2. Add the PINs the user presented so far. Some initialization
        * routines need to present these PINs again because some
        * card operations may clobber the authentication state
        * (the GPK for instance) */

       if (p15_data->pin[CKU_SO].len)
               sc_pkcs15init_set_pin_data(profile, SC_PKCS15INIT_SO_PIN,
                       p15_data->pin[CKU_SO].value, p15_data->pin[CKU_SO].len);
       if (p15_data->pin[CKU_USER].len)
               sc_pkcs15init_set_pin_data(profile, SC_PKCS15INIT_USER_PIN,
                       p15_data->pin[CKU_USER].value, p15_data->pin[CKU_USER].len);

       switch(attr->type)
       {
       case CKA_LABEL:
               rc = sc_pkcs15init_change_attrib(fw_data->p15_card, profile, p15_object,
                       P15_ATTR_TYPE_LABEL, attr->pValue, attr->ulValueLen);
               break;
       case CKA_ID:
               if (attr->ulValueLen > SC_PKCS15_MAX_ID_SIZE) {
                       rc = SC_ERROR_INVALID_ARGUMENTS;
                       break;
               }
               memcpy(id.value, attr->pValue, attr->ulValueLen);
               id.len = attr->ulValueLen;
               rc = sc_pkcs15init_change_attrib(fw_data->p15_card, profile, p15_object,
                       P15_ATTR_TYPE_ID, &id, sizeof(id));
               break;
	case CKA_SUBJECT:
		rc = SC_SUCCESS;
		break;
       default:
               rv = CKR_ATTRIBUTE_READ_ONLY;
               goto set_attr_done;
       }

       rv = sc_to_cryptoki_error(rc, p11card->reader);

set_attr_done:
	sc_unlock(p11card->card);
       sc_pkcs15init_unbind(profile);

       return rv;
#endif
}

/*
 * PKCS#15 Certificate Object
 */

void pkcs15_cert_release(void *obj)
{
	struct pkcs15_cert_object *cert = (struct pkcs15_cert_object *) obj;
	struct sc_pkcs15_cert *cert_data = cert->cert_data;

	if (__pkcs15_release_object((struct pkcs15_any_object *) obj) == 0)
		sc_pkcs15_free_certificate(cert_data);
}

CK_RV pkcs15_cert_set_attribute(struct sc_pkcs11_session *session,
                               void *object,
                               CK_ATTRIBUTE_PTR attr)
{
       struct pkcs15_cert_object *cert = (struct pkcs15_cert_object*) object;
       return pkcs15_set_attrib(session, cert->base.p15_object, attr);
}

CK_RV pkcs15_cert_get_attribute(struct sc_pkcs11_session *session,
				void *object,
				CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_cert_object *cert = (struct pkcs15_cert_object*) object;
	size_t len;

	switch (attr->type) {
	case CKA_CLASS:
		check_attribute_buffer(attr, sizeof(CK_OBJECT_CLASS));
		*(CK_OBJECT_CLASS*)attr->pValue = CKO_CERTIFICATE;
                break;
	case CKA_TOKEN:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = TRUE;
                break;
	case CKA_PRIVATE:
	case CKA_MODIFIABLE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = FALSE;
                break;
	case CKA_LABEL:
		len = strlen(cert->cert_p15obj->label);
		check_attribute_buffer(attr, len);
                memcpy(attr->pValue, cert->cert_p15obj->label, len);
                break;
	case CKA_CERTIFICATE_TYPE:
		check_attribute_buffer(attr, sizeof(CK_CERTIFICATE_TYPE));
                *(CK_CERTIFICATE_TYPE*)attr->pValue = CKC_X_509;
		break;
	case CKA_ID:
		/* Not sure why CA certs should be reported with an
		 * ID of 00. --okir 20030413 */
		if (cert->cert_info->authority) {
			check_attribute_buffer(attr, 1);
			*(unsigned char*)attr->pValue = 0;
		} else {
			check_attribute_buffer(attr, cert->cert_info->id.len);
			memcpy(attr->pValue, cert->cert_info->id.value, cert->cert_info->id.len);
                }
                break;
	case CKA_TRUSTED:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = cert->cert_info->authority?TRUE:FALSE;
                break;
	case CKA_VALUE:
		check_attribute_buffer(attr, cert->cert_data->data_len);
		memcpy(attr->pValue, cert->cert_data->data, cert->cert_data->data_len);
		break;
	case CKA_SERIAL_NUMBER:
		 check_attribute_buffer(attr, cert->cert_data->serial_len);
		 memcpy(attr->pValue, cert->cert_data->serial, cert->cert_data->serial_len);
		 break;
	case CKA_SUBJECT:
		 return asn1_sequence_wrapper(cert->cert_data->subject,
				 cert->cert_data->subject_len,
				 attr);
	case CKA_ISSUER:
		 return asn1_sequence_wrapper(cert->cert_data->issuer,
				 cert->cert_data->issuer_len,
				 attr);
	default:
                return CKR_ATTRIBUTE_TYPE_INVALID;
	}

        return CKR_OK;
}

static int
pkcs15_cert_cmp_attribute(struct sc_pkcs11_session *session,
				void *object,
				CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_cert_object *cert = (struct pkcs15_cert_object*) object;
	u8	*data;
	size_t	len;

	switch (attr->type) {
	/* Check the issuer. Some pkcs11 callers (i.e. netscape) will pass
	 * in the ASN.1 encoded SEQUENCE OF SET ... while OpenSC just
	 * keeps the SET in the issuer field. */
	case CKA_ISSUER:
		if (cert->cert_data->issuer_len == 0)
			break;
		data = (u8 *) attr->pValue;
		len = attr->ulValueLen;
		/* SEQUENCE is tag 0x30, SET is 0x31
		 * I know this code is icky, but hey... this is netscape
		 * we're dealing with :-) */
		if (cert->cert_data->issuer[0] == 0x31
		 && data[0] == 0x30 && len >= 2) {
			/* skip the length byte(s) */
			len = (data[1] & 0x80)? (data[1] & 0x7F) : 0;
			if (attr->ulValueLen < len + 2)
				break;
			data += len + 2;
			len = attr->ulValueLen - len - 2;
		}
		if (len == cert->cert_data->issuer_len
		 && !memcmp(cert->cert_data->issuer, data, len))
			return 1;
		break;
	default:
                return sc_pkcs11_any_cmp_attribute(session, object, attr);
	}

        return 0;
}

struct sc_pkcs11_object_ops pkcs15_cert_ops = {
	pkcs15_cert_release,
        pkcs15_cert_set_attribute,
	pkcs15_cert_get_attribute,
	pkcs15_cert_cmp_attribute,
	NULL,
	NULL,
        NULL
};

/*
 * PKCS#15 Private Key Object
 */
void pkcs15_prkey_release(void *object)
{
	__pkcs15_release_object((struct pkcs15_any_object *) object);
}

CK_RV pkcs15_prkey_set_attribute(struct sc_pkcs11_session *session,
                               void *object,
                               CK_ATTRIBUTE_PTR attr)
{
       struct pkcs15_prkey_object *prkey = (struct pkcs15_prkey_object*) object;
       return pkcs15_set_attrib(session, prkey->base.p15_object, attr);
}

CK_RV pkcs15_prkey_get_attribute(struct sc_pkcs11_session *session,
				void *object,
				CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_prkey_object *prkey = (struct pkcs15_prkey_object*) object;
	struct sc_pkcs15_pubkey *key = NULL;
	unsigned int usage;
	size_t len;

	if (prkey->prv_cert && prkey->prv_cert->cert_data)
		key = &prkey->prv_cert->cert_data->key;
	else if (prkey->prv_pubkey)
		key = prkey->prv_pubkey->pub_data;

	switch (attr->type) {
	case CKA_CLASS:
		check_attribute_buffer(attr, sizeof(CK_OBJECT_CLASS));
		*(CK_OBJECT_CLASS*)attr->pValue = CKO_PRIVATE_KEY;
                break;
	case CKA_TOKEN:
	case CKA_LOCAL:
	case CKA_SENSITIVE:
	case CKA_ALWAYS_SENSITIVE:
	case CKA_NEVER_EXTRACTABLE:
	case CKA_PRIVATE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = TRUE;
                break;
	case CKA_MODIFIABLE:
	case CKA_EXTRACTABLE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = FALSE;
                break;
	case CKA_LABEL:
		len = strlen(prkey->prv_p15obj->label);
		check_attribute_buffer(attr, len);
                memcpy(attr->pValue, prkey->prv_p15obj->label, len);
		break;
	case CKA_KEY_TYPE:
		check_attribute_buffer(attr, sizeof(CK_KEY_TYPE));
                *(CK_KEY_TYPE*)attr->pValue = CKK_RSA;
                break;
	case CKA_ID:
		check_attribute_buffer(attr, prkey->prv_info->id.len);
		memcpy(attr->pValue, prkey->prv_info->id.value, prkey->prv_info->id.len);
                break;
	case CKA_KEY_GEN_MECHANISM:
		check_attribute_buffer(attr, sizeof(CK_MECHANISM_TYPE));
                *(CK_MECHANISM_TYPE*)attr->pValue = CK_UNAVAILABLE_INFORMATION;
		break;
	case CKA_ENCRYPT:
	case CKA_DECRYPT:
	case CKA_SIGN:
	case CKA_SIGN_RECOVER:
	case CKA_WRAP:
	case CKA_UNWRAP:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
	case CKA_DERIVE:
		/* Combine the usage bits of all split keys */
		for (usage = 0; prkey; prkey = prkey->prv_next)
			usage |= prkey->prv_info->usage;
		return get_usage_bit(usage, attr);
	case CKA_MODULUS:
		return get_modulus(key, attr);
	case CKA_MODULUS_BITS:
		check_attribute_buffer(attr, sizeof(CK_ULONG));
		*(CK_ULONG *) attr->pValue = prkey->prv_info->modulus_length;
		return CKR_OK;
	case CKA_PUBLIC_EXPONENT:
		return get_public_exponent(key, attr);
	case CKA_PRIVATE_EXPONENT:
	case CKA_PRIME_1:
	case CKA_PRIME_2:
	case CKA_EXPONENT_1:
	case CKA_EXPONENT_2:
	case CKA_COEFFICIENT:
		return CKR_ATTRIBUTE_SENSITIVE;
	case CKA_SUBJECT:
	case CKA_START_DATE:
	case CKA_END_DATE:
		attr->ulValueLen = 0;
		return CKR_OK;
	default:
                return CKR_ATTRIBUTE_TYPE_INVALID;
	}

        return CKR_OK;
}

CK_RV pkcs15_prkey_sign(struct sc_pkcs11_session *ses, void *obj,
			CK_MECHANISM_PTR pMechanism, CK_BYTE_PTR pData,
			CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
			CK_ULONG_PTR pulDataLen)
{
	struct pkcs15_prkey_object *prkey = (struct pkcs15_prkey_object *) obj;
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) ses->slot->card->fw_data;
	struct pkcs15_slot_data *data = slot_data(ses->slot->fw_data);
	int rv, flags = 0;

	sc_debug(context, "Initiating signing operation, mechanism 0x%x.\n",
				pMechanism->mechanism);

	/* If this key requires user consent for every N operations,
	 * we may have to present the PIN again and again.
	 * For now, we require that either the terminal has a key pad,
	 * or the user allows pin caching. We may want to add GUI
	 * function pointers though.
	 */
	if (prkey->prv_p15obj->user_consent) {
		/* XXX we should really keep track how often the key
		 * is used, and how often we need to ask the user for
		 * her PIN. 
		 * For now, we just assume user_consent is 1.
		 */
		/* XXX - do we require an sc_lock here? */
		rv = revalidate_pin(data, ses);
		if (rv < 0)
			return sc_to_cryptoki_error(rv, ses->slot->card->reader);
	}

	/* See which of the alternative keys supports signing */
	while (prkey
	 && !(prkey->prv_info->usage
	     & (SC_PKCS15_PRKEY_USAGE_SIGN|SC_PKCS15_PRKEY_USAGE_SIGNRECOVER|
	     	SC_PKCS15_PRKEY_USAGE_NONREPUDIATION))) 
		prkey = prkey->prv_next;

	if (prkey == NULL)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	switch (pMechanism->mechanism) {
	case CKM_RSA_PKCS:
		/* Um. We need to guess what netscape is trying to
		 * sign here. We're lucky that all these things have
		 * different sizes. */
		flags = SC_ALGORITHM_RSA_PAD_PKCS1;
		switch (ulDataLen) {
		case 34:flags |= SC_ALGORITHM_RSA_HASH_MD5;  /* MD5 + header */
			pData += 18; ulDataLen -= 18;
			break;
		case 35:
			if (pData[7] == 0x24)
				flags |= SC_ALGORITHM_RSA_HASH_RIPEMD160;   /* RIPEMD160 + hdr */
			else
				flags |= SC_ALGORITHM_RSA_HASH_SHA1;   /* SHA1 + hdr */
			pData += 15; ulDataLen -= 15;
			break;
		case 36:flags |= SC_ALGORITHM_RSA_HASH_MD5_SHA1; /* SSL hash */
			break;
		case 20:
			flags |= SC_ALGORITHM_RSA_HASH_SHA1;	/* SHA1 */
			break;
		case 16:
			flags |= SC_ALGORITHM_RSA_HASH_MD5;	/* MD5 */
			break;
		default:
			flags |= SC_ALGORITHM_RSA_HASH_NONE;
		}
		break;
	case CKM_MD5_RSA_PKCS:
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_MD5;
		break;
	case CKM_SHA1_RSA_PKCS:
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA1;
		break;
	case CKM_RIPEMD160_RSA_PKCS:
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_RIPEMD160;
		break;
	case CKM_RSA_X_509:
		flags = SC_ALGORITHM_RSA_RAW;
		break;
	default:
                return CKR_MECHANISM_INVALID;
	}

        sc_debug(context, "Selected flags %X. Now computing signature for %d bytes. %d bytes reserved.\n", flags, ulDataLen, *pulDataLen);
	rv = sc_pkcs15_compute_signature(fw_data->p15_card,
					 prkey->prv_p15obj,
					 flags,
					 pData,
					 ulDataLen,
					 pSignature,
					 *pulDataLen);

	/* Do we have to try a re-login and then try to sign again? */
	if (rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) {
		/* Ensure that revalidate_pin() doesn't do a final sc_unlock()
		   that would clear the card's current_path */
		rv = sc_lock(ses->slot->card->card);
		if (rv < 0)
			return sc_to_cryptoki_error(rv, ses->slot->card->reader);

		rv = revalidate_pin(data, ses);
		if (rv == 0)
			rv = sc_pkcs15_compute_signature(fw_data->p15_card,
				prkey->prv_p15obj, flags, pData, ulDataLen,
				pSignature, *pulDataLen);

		sc_unlock(ses->slot->card->card);
	}

        sc_debug(context, "Sign complete. Result %d.\n", rv);

	if (rv > 0) {
                *pulDataLen = rv;
                return CKR_OK;
	}

        return sc_to_cryptoki_error(rv, ses->slot->card->reader);
}

static CK_RV
pkcs15_prkey_unwrap(struct sc_pkcs11_session *ses, void *obj,
		CK_MECHANISM_PTR pMechanism,
		CK_BYTE_PTR pData, CK_ULONG ulDataLen,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount,
		void **result)
{
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) ses->slot->card->fw_data;
	struct pkcs15_prkey_object *prkey;
	struct pkcs15_slot_data *data = slot_data(ses->slot->fw_data);
	u8	unwrapped_key[256];
	int	rv;

	sc_debug(context, "Initiating key unwrap.\n");

	/* See which of the alternative keys supports unwrap */
	prkey = (struct pkcs15_prkey_object *) obj;
	while (prkey
	 && !(prkey->prv_info->usage
	     & (SC_PKCS15_PRKEY_USAGE_DECRYPT|SC_PKCS15_PRKEY_USAGE_UNWRAP)))
		prkey = prkey->prv_next;

	if (prkey == NULL)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;


	if (pMechanism->mechanism != CKM_RSA_PKCS)
		return CKR_MECHANISM_INVALID;

	rv = sc_pkcs15_decipher(fw_data->p15_card, prkey->prv_p15obj,
				 SC_ALGORITHM_RSA_PAD_PKCS1,
				 pData, ulDataLen,
				 unwrapped_key, sizeof(unwrapped_key));

	/* Do we have to try a re-login and then try to decrypt again? */
	if (rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) {
		/* Ensure that revalidate_pin() doesn't do a final sc_unlock()
		   that would clear the card's current_path */
		rv = sc_lock(ses->slot->card->card);
		if (rv < 0)
			return sc_to_cryptoki_error(rv, ses->slot->card->reader);

		rv = revalidate_pin(data, ses);
		if (rv == 0)
			rv = sc_pkcs15_decipher(fw_data->p15_card, prkey->prv_p15obj,
						SC_ALGORITHM_RSA_PAD_PKCS1,
						pData, ulDataLen,
						unwrapped_key, sizeof(unwrapped_key));

		sc_unlock(ses->slot->card->card);
	}

	sc_debug(context, "Key unwrap complete. Result %d.\n", rv);

	if (rv < 0)
		return sc_to_cryptoki_error(rv, ses->slot->card->reader);
	return sc_pkcs11_create_secret_key(ses,
			unwrapped_key, rv,
			pTemplate, ulAttributeCount,
			(struct sc_pkcs11_object **) result);
}

struct sc_pkcs11_object_ops pkcs15_prkey_ops = {
	pkcs15_prkey_release,
	pkcs15_prkey_set_attribute,
	pkcs15_prkey_get_attribute,
	sc_pkcs11_any_cmp_attribute,
	NULL,
	NULL,
        pkcs15_prkey_sign,
	pkcs15_prkey_unwrap
};

/*
 * PKCS#15 RSA Public Key Object
 */
void pkcs15_pubkey_release(void *object)
{
	struct pkcs15_pubkey_object *pubkey = (struct pkcs15_pubkey_object*) object;
	struct sc_pkcs15_pubkey *key_data = pubkey->pub_data;

	if (__pkcs15_release_object((struct pkcs15_any_object *) object) == 0)
		sc_pkcs15_free_pubkey(key_data);
}

CK_RV pkcs15_pubkey_set_attribute(struct sc_pkcs11_session *session,
                               void *object,
                               CK_ATTRIBUTE_PTR attr)
{
       struct pkcs15_pubkey_object *pubkey = (struct pkcs15_pubkey_object*) object;
       return pkcs15_set_attrib(session, pubkey->base.p15_object, attr);
}

CK_RV pkcs15_pubkey_get_attribute(struct sc_pkcs11_session *session,
				void *object,
				CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_pubkey_object *pubkey = (struct pkcs15_pubkey_object*) object;
	struct pkcs15_cert_object *cert = pubkey->pub_cert;
	size_t len;

	switch (attr->type) {
	case CKA_CLASS:
		check_attribute_buffer(attr, sizeof(CK_OBJECT_CLASS));
		*(CK_OBJECT_CLASS*)attr->pValue = CKO_PUBLIC_KEY;
                break;
	case CKA_TOKEN:
	case CKA_LOCAL:
	case CKA_SENSITIVE:
	case CKA_ALWAYS_SENSITIVE:
	case CKA_NEVER_EXTRACTABLE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = TRUE;
                break;
	case CKA_PRIVATE:
	case CKA_MODIFIABLE:
	case CKA_EXTRACTABLE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = FALSE;
                break;
	case CKA_LABEL:
		if (pubkey->pub_p15obj) {
			len = strlen(pubkey->pub_p15obj->label);
			check_attribute_buffer(attr, len);
			memcpy(attr->pValue, pubkey->pub_p15obj->label, len);
		} else if (cert && cert->cert_p15obj) {
			len = strlen(cert->cert_p15obj->label);
			check_attribute_buffer(attr, len);
			memcpy(attr->pValue, cert->cert_p15obj->label, len);
		} else {
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
		break;
	case CKA_KEY_TYPE:
		check_attribute_buffer(attr, sizeof(CK_KEY_TYPE));
                *(CK_KEY_TYPE*)attr->pValue = CKK_RSA;
                break;
	case CKA_ID:
		if (pubkey->pub_info) {
			check_attribute_buffer(attr, pubkey->pub_info->id.len);
			memcpy(attr->pValue, pubkey->pub_info->id.value, pubkey->pub_info->id.len);
		} else if (cert && cert->cert_info) {
			check_attribute_buffer(attr, cert->cert_info->id.len);
			memcpy(attr->pValue, cert->cert_info->id.value, cert->cert_info->id.len);
		} else {
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
                break;
	case CKA_KEY_GEN_MECHANISM:
		check_attribute_buffer(attr, sizeof(CK_MECHANISM_TYPE));
                *(CK_MECHANISM_TYPE*)attr->pValue = CK_UNAVAILABLE_INFORMATION;
		break;
	case CKA_ENCRYPT:
	case CKA_DECRYPT:
	case CKA_SIGN:
	case CKA_SIGN_RECOVER:
	case CKA_WRAP:
	case CKA_UNWRAP:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
	case CKA_DERIVE:
		if (pubkey->pub_info) {
			return get_usage_bit(pubkey->pub_info->usage, attr);
		} else {
			return get_usage_bit(SC_PKCS15_PRKEY_USAGE_ENCRYPT
					|SC_PKCS15_PRKEY_USAGE_VERIFY
					|SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER,
					attr);
		}
	case CKA_MODULUS:
		return get_modulus(pubkey->pub_data, attr);
	case CKA_MODULUS_BITS:
		return get_modulus_bits(pubkey->pub_data, attr);
	case CKA_PUBLIC_EXPONENT:
		return get_public_exponent(pubkey->pub_data, attr);
	case CKA_VALUE:
		if (pubkey->pub_data) {
			check_attribute_buffer(attr, pubkey->pub_data->data.len);
			memcpy(attr->pValue, pubkey->pub_data->data.value,
					      pubkey->pub_data->data.len);
		} else if (cert && cert->cert_data) {
			check_attribute_buffer(attr, cert->cert_data->data_len);
			memcpy(attr->pValue, cert->cert_data->data, cert->cert_data->data_len);
		}
		break;
	default:
                return CKR_ATTRIBUTE_TYPE_INVALID;
	}

        return CKR_OK;
}

struct sc_pkcs11_object_ops pkcs15_pubkey_ops = {
	pkcs15_pubkey_release,
	pkcs15_pubkey_set_attribute,
	pkcs15_pubkey_get_attribute,
	sc_pkcs11_any_cmp_attribute,
	NULL,
	NULL,
        NULL
};

/*
 * get_attribute helpers
 */
static CK_RV
get_bignum(sc_pkcs15_bignum_t *bn, CK_ATTRIBUTE_PTR attr)
{
	check_attribute_buffer(attr, bn->len);
	memcpy(attr->pValue, bn->data, bn->len);
	return CKR_OK;
}

static CK_RV
get_bignum_bits(sc_pkcs15_bignum_t *bn, CK_ATTRIBUTE_PTR attr)
{
	CK_ULONG	bits, mask;

	bits = bn->len * 8;
	for (mask = 0x80; mask; mask >>= 1, bits--) {
		if (bn->data[0] & mask)
			break;
	}
	check_attribute_buffer(attr, sizeof(bits));
	*(CK_ULONG *) attr->pValue = bits;
	return CKR_OK;
}

static CK_RV
get_modulus(struct sc_pkcs15_pubkey *key, CK_ATTRIBUTE_PTR attr)
{
	if (key == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		return get_bignum(&key->u.rsa.modulus, attr);
	}
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV
get_modulus_bits(struct sc_pkcs15_pubkey *key, CK_ATTRIBUTE_PTR attr)
{
	if (key == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		return get_bignum_bits(&key->u.rsa.modulus, attr);
	}
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV
get_public_exponent(struct sc_pkcs15_pubkey *key, CK_ATTRIBUTE_PTR attr)
{
	if (key == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	switch (key->algorithm) {
	case SC_ALGORITHM_RSA:
		return get_bignum(&key->u.rsa.exponent, attr);
	}
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

/*
 * Map pkcs15 usage bits to pkcs11 usage attributes.
 *
 * It's not totally clear to me whether SC_PKCS15_PRKEY_USAGE_NONREPUDIATION should
 * be treated as being equivalent with CKA_SIGN or not...
 */
static CK_RV
get_usage_bit(unsigned int usage, CK_ATTRIBUTE_PTR attr)
{
	static struct {
		CK_ATTRIBUTE_TYPE type;
		unsigned int	flag;
	} flag_mapping[] = {
	      	{ CKA_ENCRYPT,		SC_PKCS15_PRKEY_USAGE_ENCRYPT },
	      	{ CKA_DECRYPT,		SC_PKCS15_PRKEY_USAGE_DECRYPT },
		{ CKA_SIGN,		SC_PKCS15_PRKEY_USAGE_SIGN|SC_PKCS15_PRKEY_USAGE_NONREPUDIATION },
		{ CKA_SIGN_RECOVER,	SC_PKCS15_PRKEY_USAGE_SIGNRECOVER },
		{ CKA_WRAP,		SC_PKCS15_PRKEY_USAGE_WRAP },
		{ CKA_UNWRAP,		SC_PKCS15_PRKEY_USAGE_UNWRAP },
		{ CKA_VERIFY,		SC_PKCS15_PRKEY_USAGE_VERIFY },
		{ CKA_VERIFY_RECOVER,	SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER },
		{ CKA_DERIVE,		SC_PKCS15_PRKEY_USAGE_DERIVE },
		{ 0, 0 }
	};
	unsigned int mask = 0, j;

	for (j = 0; (mask = flag_mapping[j].flag) != 0; j++) {
		if (flag_mapping[j].type == attr->type)
			break;
	}
	if (mask == 0)
		return CKR_ATTRIBUTE_TYPE_INVALID;

	check_attribute_buffer(attr, sizeof(CK_BBOOL));
	*(CK_BBOOL*)attr->pValue = (usage & mask)? TRUE : FALSE;

	return CKR_OK;
}


static CK_RV
asn1_sequence_wrapper(const u8 *data, size_t len, CK_ATTRIBUTE_PTR attr)
{
	u8		*dest;
	unsigned int	n;
	size_t		len2;

	len2 = len;
	check_attribute_buffer(attr, len + 1 + sizeof(len));

	dest = (u8 *) attr->pValue;
	*dest++ = 0x30;	/* SEQUENCE tag */
	if (len <= 127) {
		*dest++ = len;
	} else {
		for (n = 4; (len & 0xFF000000) == 0; n--)
			len <<= 8;
		*dest++ = 0x80 + n;
		while (n--) {
			*dest++ = len >> 24;
			len <<= 8;
		}
	}
	memcpy(dest, data, len2);
	attr->ulValueLen = (dest - (u8 *) attr->pValue) + len2;
	return CKR_OK;
}

static void
cache_pin(void *p, int user, const void *pin, size_t len)
{
	struct pkcs15_slot_data *data = (struct pkcs15_slot_data *) p;

	if ((user != 0 && user != 1) || !sc_pkcs11_conf.cache_pins)
		return;
	memset(data->pin + user, 0, sizeof(data->pin[user]));
	if (len && len <= MAX_CACHE_PIN) {
		memcpy(data->pin[user].value, pin, len);
		data->pin[user].len = len;
	}
}

static int
revalidate_pin(struct pkcs15_slot_data *data, struct sc_pkcs11_session *ses)
{
	int rv;
	u8 value[MAX_CACHE_PIN];

	sc_debug(context, "revalidate_pin called\n");
	if (!sc_pkcs11_conf.cache_pins &&
	    !(ses->slot->token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH))
		return SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;

	if (ses->slot->token_info.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
		rv = pkcs15_login(ses->slot->card, ses->slot->fw_data, CKU_USER, NULL, 0);
	else {
		memcpy(value, data->pin[CKU_USER].value, data->pin[CKU_USER].len);
		rv = pkcs15_login(ses->slot->card, ses->slot->fw_data, CKU_USER,
			value, data->pin[CKU_USER].len);
	}

	if (rv != CKR_OK)
		sc_debug(context, "Re-login failed: 0x%0x (%d)\n", rv, rv);

	return rv;
}

/*
 * Mechanism handling
 * FIXME: We should consult the card's algorithm list to
 * find out what operations it supports
 */
int
register_mechanisms(struct sc_pkcs11_card *p11card)
{
	sc_card_t *card = p11card->card;
	sc_algorithm_info_t *alg_info;
	CK_MECHANISM_INFO mech_info;
	sc_pkcs11_mechanism_type_t *mt;
	unsigned int num;
	int rc, flags = 0;

	/* Register generic mechanisms */
	sc_pkcs11_register_generic_mechanisms(p11card);

	mech_info.flags = CKF_HW | CKF_SIGN | CKF_UNWRAP;
#ifdef HAVE_OPENSSL
	mech_info.flags |= CKF_VERIFY;
#endif
	mech_info.ulMinKeySize = ~0;
	mech_info.ulMaxKeySize = 0;

	/* For now, we just OR all the algorithm specific
	 * flags, based on the assumption that cards don't
	 * support different modes for different key sizes
	 */
	num = card->algorithm_count;
	alg_info = card->algorithms;
	while (num--) {
		if (alg_info->algorithm != SC_ALGORITHM_RSA)
			continue;
		if (alg_info->key_length < mech_info.ulMinKeySize)
			mech_info.ulMinKeySize = alg_info->key_length;
		if (alg_info->key_length > mech_info.ulMaxKeySize)
			mech_info.ulMaxKeySize = alg_info->key_length;

		flags |= alg_info->flags;
		alg_info++;
	}

	/* Check if we support raw RSA */
	if (flags & SC_ALGORITHM_RSA_RAW) {
		mt = sc_pkcs11_new_fw_mechanism(CKM_RSA_X_509,
					&mech_info, CKK_RSA, NULL);
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;

		/* If the card supports RAW, it should be all means
		 * have registered everything else, too. If it didn't
		 * we help it a little
		 */
		flags |= SC_ALGORITHM_RSA_PAD_PKCS1
			|SC_ALGORITHM_RSA_HASHES;
	}

	/* Check for PKCS1 */
	if (flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
		mt = sc_pkcs11_new_fw_mechanism(CKM_RSA_PKCS,
					&mech_info, CKK_RSA, NULL);
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;

		/* if the driver doesn't say what hashes it supports,
		 * claim we will do all of them */
		if (!(flags & SC_ALGORITHM_RSA_HASHES))
			flags |= SC_ALGORITHM_RSA_HASHES;

		if (flags & SC_ALGORITHM_RSA_HASH_SHA1)
			sc_pkcs11_register_sign_and_hash_mechanism(p11card,
					CKM_SHA1_RSA_PKCS, CKM_SHA_1, mt);
		if (flags & SC_ALGORITHM_RSA_HASH_MD5)
			sc_pkcs11_register_sign_and_hash_mechanism(p11card,
					CKM_MD5_RSA_PKCS, CKM_MD5, mt);
		if (flags & SC_ALGORITHM_RSA_HASH_RIPEMD160)
			sc_pkcs11_register_sign_and_hash_mechanism(p11card,
					CKM_RIPEMD160_RSA_PKCS, CKM_RIPEMD160, mt);
#if 0
		/* Does this correspond to any defined CKM_XXX value? */
		if (flags & SC_ALGORITHM_RSA_HASH_MD5_SHA1)
			sc_pkcs11_register_sign_and_hash_mechanism(p11card,
					CKM_XXX_RSA_PKCS, CKM_XXX, mt);
#endif

#ifdef HAVE_OPENSSL
		mech_info.flags = CKF_GENERATE_KEY_PAIR;
		mt = sc_pkcs11_new_fw_mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN,
					&mech_info, CKK_RSA, NULL);
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;
#endif
	}

	return CKR_OK;
}

int
lock_card(struct pkcs15_fw_data *fw_data)
{
	int	rc;

	if ((rc = sc_lock(fw_data->p15_card->card)) < 0)
		sc_debug(context, "Failed to lock card (%d)\n", rc);
	else
		fw_data->locked++;

	return rc;
}

int
unlock_card(struct pkcs15_fw_data *fw_data)
{
	while (fw_data->locked) {
		sc_unlock(fw_data->p15_card->card);
		fw_data->locked--;
	}
	return 0;
}
