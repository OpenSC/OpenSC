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

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "sc-pkcs11.h"
#ifdef USE_PKCS15_INIT
#include "pkcs15init/pkcs15-init.h"
#endif

extern int hack_enabled;

struct pkcs15_slot_data {
	struct sc_pkcs15_object *auth_obj;
};
#define slot_data(p)		((struct pkcs15_slot_data *) (p))
#define slot_data_auth(p)	(((p) && slot_data(p)) ? slot_data(p)->auth_obj : NULL)
#define slot_data_pin_info(p)	(((p) && slot_data_auth(p))? \
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
	unsigned char user_puk[64];
	unsigned int user_puk_len;
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
#define cert_prvkey		base.related_privkey

struct pkcs15_prkey_object {
	struct pkcs15_any_object	base;

	struct sc_pkcs15_prkey_info *	prv_info;
};
#define prv_flags		base.base.flags
#define prv_p15obj		base.p15_object
#define prv_pubkey		base.related_pubkey
#define prv_next		base.related_privkey

struct pkcs15_pubkey_object {
	struct pkcs15_any_object	base;

	struct sc_pkcs15_pubkey_info *	pub_info;	/* NULL for key extracted from cert */
	struct sc_pkcs15_pubkey *	pub_data;
};
#define pub_flags		base.base.flags
#define pub_p15obj		base.p15_object
#define pub_genfrom		base.related_cert

#define __p15_type(obj)		(((obj) && (obj)->p15_object)? ((obj)->p15_object->type) : (unsigned int)-1)
#define is_privkey(obj)		((__p15_type(obj) & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_PRKEY)
#define is_pubkey(obj)		((__p15_type(obj) & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_PUBKEY)
#define is_cert(obj)		(__p15_type(obj) == SC_PKCS15_TYPE_CERT_X509)

struct pkcs15_data_object {
	struct pkcs15_any_object	base;

	struct sc_pkcs15_data_info *info;
	struct sc_pkcs15_data *value;
};
#define data_flags		base.base.flags
#define data_p15obj		base.p15_object
#define is_data(obj) (__p15_type(obj) == SC_PKCS15_TYPE_DATA_OBJECT)

extern struct sc_pkcs11_object_ops pkcs15_cert_ops;
extern struct sc_pkcs11_object_ops pkcs15_prkey_ops;
extern struct sc_pkcs11_object_ops pkcs15_pubkey_ops;
extern struct sc_pkcs11_object_ops pkcs15_dobj_ops;

#define GOST_PARAMS_OID_SIZE 9
static const struct {
	const CK_BYTE oid[GOST_PARAMS_OID_SIZE];
	unsigned char param;
} gostr3410_param_oid [] = {
	{ { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01 },
		SC_PKCS15_PARAMSET_GOSTR3410_A },
	{ { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x02 },
		SC_PKCS15_PARAMSET_GOSTR3410_B },
	{ { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x03 },
		SC_PKCS15_PARAMSET_GOSTR3410_C }
};

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
static CK_RV	get_gostr3410_params(const u8 *, size_t, CK_ATTRIBUTE_PTR);
static CK_RV	get_ec_pubkey_point(struct sc_pkcs15_pubkey *, CK_ATTRIBUTE_PTR);
static CK_RV	get_ec_pubkey_params(struct sc_pkcs15_pubkey *, CK_ATTRIBUTE_PTR);
static int	lock_card(struct pkcs15_fw_data *);
static int	unlock_card(struct pkcs15_fw_data *);
static int	reselect_app_df(sc_pkcs15_card_t *p15card);

/* PKCS#15 Framework */

static CK_RV pkcs15_bind(struct sc_pkcs11_card *p11card)
{
	struct pkcs15_fw_data *fw_data;
	int rc;

	if (!(fw_data = calloc(1, sizeof(*fw_data))))
		return CKR_HOST_MEMORY;
	p11card->fw_data = fw_data;

	rc = sc_pkcs15_bind(p11card->card, &fw_data->p15_card);
	if (rc != SC_SUCCESS) {
		sc_debug(context, SC_LOG_DEBUG_NORMAL, "sc_pkcs15_bind failed: %d", rc);
		return sc_to_cryptoki_error(rc, NULL);
	}

	rc = register_mechanisms(p11card);
	if (rc != CKR_OK) {
		sc_debug(context, SC_LOG_DEBUG_NORMAL, "register_mechanisms failed: 0x%x", rc);
		return rc;
	}

	return CKR_OK;
}

static CK_RV pkcs15_unbind(struct sc_pkcs11_card *p11card)
{
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	unsigned int i;
	int rc;

	for (i = 0; i < fw_data->num_objects; i++) {
		struct pkcs15_any_object *obj = fw_data->objects[i];

		/* use object specific release method if existing */
		if (obj->base.ops && obj->base.ops->release)
			obj->base.ops->release(obj);
		else
			__pkcs15_release_object(obj);
	}

	unlock_card(fw_data);

	rc = sc_pkcs15_unbind(fw_data->p15_card);
	free(fw_data);
	return sc_to_cryptoki_error(rc, NULL);
}

static void pkcs15_init_token_info(struct sc_pkcs15_card *p15card, CK_TOKEN_INFO_PTR pToken)
{
	strcpy_bp(pToken->manufacturerID, p15card->tokeninfo->manufacturer_id, 32);
	if (p15card->flags & SC_PKCS15_CARD_FLAG_EMULATED)
		strcpy_bp(pToken->model, "PKCS#15 emulated", 16);
	else
		strcpy_bp(pToken->model, "PKCS#15", 16);

	/* Take the last 16 chars of the serial number (if the are more
	 * than 16).
	 * _Assuming_ that the serial number is a Big Endian counter, this
	 * will assure that the serial within each type of card will be
	 * unique in pkcs11 (at least for the first 8^16 cards :-) */
	if (p15card->tokeninfo->serial_number != NULL) {
		int sn_start = strlen(p15card->tokeninfo->serial_number) - 16;

		if (sn_start < 0)
			sn_start = 0;
		strcpy_bp(pToken->serialNumber, p15card->tokeninfo->serial_number + sn_start, 16);
	}

	pToken->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	pToken->ulSessionCount = 0; /* FIXME */
	pToken->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	pToken->ulRwSessionCount = 0; /* FIXME */
	pToken->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pToken->hardwareVersion.major = 0;
	pToken->hardwareVersion.minor = 0;
	pToken->firmwareVersion.major = 0;
	pToken->firmwareVersion.minor = 0;
}

static char *
set_cka_label(CK_ATTRIBUTE_PTR attr, char *label) 
{ 
	char *l = (char *)attr->pValue; 
	int len = attr->ulValueLen; 

	if (len >= SC_PKCS15_MAX_LABEL_SIZE) 
		len = SC_PKCS15_MAX_LABEL_SIZE-1; 
	memcpy(label, l, len); 
	label[len] = '\0'; 
	return label; 
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

	if (!(obj = calloc(1, size)))
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
	
	sc_mem_clear(obj, obj->size);
	free(obj);

	return 0;
}

static int
__pkcs15_delete_object(struct pkcs15_fw_data *fw_data, struct pkcs15_any_object *obj)
{
	unsigned int i;

	if (fw_data->num_objects == 0)
		return SC_ERROR_INTERNAL;

	for (i = 0; i < fw_data->num_objects; ++i)
		if (fw_data->objects[i] == obj) {
			fw_data->objects[i] = fw_data->objects[--fw_data->num_objects];
			if (__pkcs15_release_object(obj) > 0)
				return SC_ERROR_INTERNAL;
			return SC_SUCCESS;
		}
	return SC_ERROR_OBJECT_NOT_FOUND;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	struct sc_pkcs11_slot *slot;
	struct sc_pkcs15_object *auth;
	struct sc_pkcs15_pin_info *pin_info;
	struct sc_pin_cmd_data data;
	int r;
	CK_RV rv;

	if (pInfo == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	sc_debug(context, SC_LOG_DEBUG_NORMAL, "C_GetTokenInfo(%lx)", slotID);

	rv = slot_get_token(slotID, &slot);
	if (rv != CKR_OK)
		goto out;

	/* User PIN flags are cleared before re-calculation */
	slot->token_info.flags &= ~(CKF_USER_PIN_COUNT_LOW|CKF_USER_PIN_FINAL_TRY|CKF_USER_PIN_LOCKED);
	auth = slot_data_auth(slot->fw_data);
	if (auth) {
		pin_info = (struct sc_pkcs15_pin_info*) auth->data;

		/* Try to update PIN info from card */
		memset(&data, 0, sizeof(data));
		data.cmd = SC_PIN_CMD_GET_INFO;
		data.pin_type = SC_AC_CHV;
		data.pin_reference = pin_info->reference;

		r = sc_pin_cmd(slot->card->card, &data, NULL);
		if (r == SC_SUCCESS) {
			if (data.pin1.max_tries > 0)
				pin_info->max_tries = data.pin1.max_tries;
			/* tries_left must be supported or sc_pin_cmd should not return SC_SUCCESS */
			pin_info->tries_left = data.pin1.tries_left;
		}

		if (pin_info->tries_left >= 0) {
			if (pin_info->tries_left == 1 || pin_info->max_tries == 1)
				slot->token_info.flags |= CKF_USER_PIN_FINAL_TRY;
			else if (pin_info->tries_left == 0)
				slot->token_info.flags |= CKF_USER_PIN_LOCKED;
			else if (pin_info->max_tries > 1 && pin_info->tries_left < pin_info->max_tries)
				slot->token_info.flags |= CKF_USER_PIN_COUNT_LOW;
		}
	}
	memcpy(pInfo, &slot->token_info, sizeof(CK_TOKEN_INFO));
out:
	sc_pkcs11_unlock();
	return rv;
}

static int public_key_created(struct pkcs15_fw_data *fw_data,
			      const unsigned int num_objects,
			      const u8 *id, 
			      const size_t size_id,
			      struct pkcs15_any_object **obj2)
{
	int found = 0;
	unsigned int ii=0;

	while(ii<num_objects && !found) {
		if (!fw_data->objects[ii]->p15_object) {
			ii++;
			continue;
		}
		if ((fw_data->objects[ii]->p15_object->type != SC_PKCS15_TYPE_PUBKEY) && 
		    (fw_data->objects[ii]->p15_object->type != SC_PKCS15_TYPE_PUBKEY_RSA) &&
		    (fw_data->objects[ii]->p15_object->type != SC_PKCS15_TYPE_PUBKEY_DSA) &&
		    (fw_data->objects[ii]->p15_object->type != SC_PKCS15_TYPE_PUBKEY_EC) &&
		    (fw_data->objects[ii]->p15_object->type != SC_PKCS15_TYPE_PUBKEY_GOSTR3410)) {
			ii++;
			continue;
		}
		/* XXX this is somewhat dirty as this assumes that the first 
		 * member of the is the pkcs15 id */
		if (memcmp(fw_data->objects[ii]->p15_object->data, id, size_id) == 0) {
			*obj2 = (struct pkcs15_any_object *) fw_data->objects[ii];
			found=1;
		} else
			ii++;
	}
  
	if (found)
		return SC_SUCCESS;
	else 
		return SC_ERROR_OBJECT_NOT_FOUND;      
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

	if (cert->flags & SC_PKCS15_CO_FLAG_PRIVATE)   	/* is the cert private? */
		p15_cert = NULL; 		/* will read cert when needed */
	else
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
	rv = public_key_created(fw_data, fw_data->num_objects, p15_info->id.value, p15_info->id.len, (struct pkcs15_any_object **) &obj2);
	
	if (rv != SC_SUCCESS)
	  rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &obj2,
				      NULL, &pkcs15_pubkey_ops,
				      sizeof(struct pkcs15_pubkey_object));
	if (rv < 0)
	  return rv;	
	
	if (p15_cert) {
		 /* we take the pubkey from the cert, as it in not needed */
		obj2->pub_data = p15_cert->key;
		/* invalidate public data of the cert object so that sc_pkcs15_cert_free
		 * does not free the public key data as well (something like
		 * sc_pkcs15_pubkey_dup would have been nice here) -- Nils
		 */
		p15_cert->key = NULL;
		
	} else
		obj2->pub_data = NULL; /* will copy from cert when cert is read */

	obj2->pub_genfrom = object;
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
	/* Attempt to read pubkey from card or file. 
	 * During initialization process, the key may have been created
	 * and saved as a file before the certificate has been created. 
	 */  
	if (pubkey->flags & SC_PKCS15_CO_FLAG_PRIVATE)   	/* is the key private? */
	  p15_key = NULL; 		/* will read key when needed */
	else {	  
		/* if emulation already created pubkey use it */
		if (pubkey->emulated && (fw_data->p15_card->flags & SC_PKCS15_CARD_FLAG_EMULATED)) {
			p15_key = (struct sc_pkcs15_pubkey *) pubkey->emulated;
			sc_debug(context, SC_LOG_DEBUG_NORMAL, "Using emulated pubkey %p", p15_key);
		}
		else {
			if ((rv = sc_pkcs15_read_pubkey(fw_data->p15_card, pubkey, &p15_key)) < 0)
				 p15_key = NULL;
		}
	}

	/* Public key object */
	rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &object,
					pubkey, &pkcs15_pubkey_ops,
					sizeof(struct pkcs15_pubkey_object));
	if (rv >= 0) {
		object->pub_info = (struct sc_pkcs15_pubkey_info *) pubkey->data;
		object->pub_data = p15_key;
		if (p15_key && object->pub_info->modulus_length == 0 
				&& p15_key->algorithm == SC_ALGORITHM_RSA) {
			object->pub_info->modulus_length = 
				8 * p15_key->u.rsa.modulus.len;
		}
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
__pkcs15_create_data_object(struct pkcs15_fw_data *fw_data,
		    struct sc_pkcs15_object *object, struct pkcs15_any_object **data_object)
{
	struct pkcs15_data_object *dobj = NULL;
	int rv;

	rv = __pkcs15_create_object(fw_data, (struct pkcs15_any_object **) &dobj,
			object, &pkcs15_dobj_ops,
			sizeof(struct pkcs15_data_object));
	if (rv >= 0)   {
	    dobj->info = (struct sc_pkcs15_data_info *) object->data;
	    dobj->value = NULL;
	}
	
	if (data_object != NULL)
		*data_object = (struct pkcs15_any_object *) dobj;
	
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
		sc_debug(context, SC_LOG_DEBUG_NORMAL, "Found %d %s%s\n", count,
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

	sc_debug(context, SC_LOG_DEBUG_NORMAL, "Object is a private key and has id %s",
	         sc_pkcs15_print_id(id));

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
		if (is_pubkey(obj) && !pk->prv_pubkey) {
			struct pkcs15_pubkey_object *pubkey;
			
			pubkey = (struct pkcs15_pubkey_object *) obj;
			if (sc_pkcs15_compare_id(&pubkey->pub_info->id, id)) {
				sc_debug(context, SC_LOG_DEBUG_NORMAL, "Associating object %d as public key", i);
				pk->prv_pubkey = pubkey;
				if (pk->prv_info->modulus_length == 0)
					pk->prv_info->modulus_length = pubkey->pub_info->modulus_length;
			}
		}
	}
}

static void
__pkcs15_cert_bind_related(struct pkcs15_fw_data *fw_data, struct pkcs15_cert_object *cert)
{
	struct sc_pkcs15_cert *c1 = cert->cert_data;
	sc_pkcs15_id_t *id = &cert->cert_info->id;
	unsigned int i;

	sc_debug(context, SC_LOG_DEBUG_NORMAL, "Object is a certificate and has id %s",
	         sc_pkcs15_print_id(id));

	/* Loop over all objects to see if we find the certificate of
	 * the issuer and the associated private key */
	for (i = 0; i < fw_data->num_objects; i++) {
		struct pkcs15_any_object *obj = fw_data->objects[i];

		if (is_cert(obj) && obj != (struct pkcs15_any_object *) cert) {
			struct pkcs15_cert_object *cert2;
			struct sc_pkcs15_cert *c2;

			cert2 = (struct pkcs15_cert_object *) obj;
			c2 = cert2->cert_data;

			if (!c1 || !c2 || !c1->issuer_len || !c2->subject_len)
				continue;
			if (c1->issuer_len == c2->subject_len
			 && !memcmp(c1->issuer, c2->subject, c1->issuer_len)) {
				sc_debug(context, SC_LOG_DEBUG_NORMAL, "Associating object %d (id %s) as issuer",
				         i, sc_pkcs15_print_id(&cert2->cert_info->id));
				cert->cert_issuer = (struct pkcs15_cert_object *) obj;
				return;
			}
		} else
		if (is_privkey(obj) && !cert->cert_prvkey) {
			struct pkcs15_prkey_object *pk;

			pk = (struct pkcs15_prkey_object *) obj;
			if (sc_pkcs15_compare_id(&pk->prv_info->id, id)) {
				sc_debug(context, SC_LOG_DEBUG_NORMAL, "Associating object %d as private key", i);
				cert->cert_prvkey = pk;
			}
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

		sc_debug(context, SC_LOG_DEBUG_NORMAL, "Looking for objects related to object %d", i);

		if (is_privkey(obj)) {
			__pkcs15_prkey_bind_related(fw_data, (struct pkcs15_prkey_object *) obj);
		} else if (is_cert(obj)) {
			__pkcs15_cert_bind_related(fw_data, (struct pkcs15_cert_object *) obj);
		}
	}
}

/* We deferred reading of the cert until needed, as it may be
 * a private object, so we must wait till login to read
 */

static int 
check_cert_data_read(struct pkcs15_fw_data *fw_data,
				 struct pkcs15_cert_object *cert)
{
	int rv;
	struct pkcs15_pubkey_object *obj2;

	if (!cert)
		return SC_ERROR_OBJECT_NOT_FOUND;

	if (cert->cert_data) 
		return 0;
	if ((rv = sc_pkcs15_read_certificate(fw_data->p15_card, 
				cert->cert_info, &cert->cert_data) < 0))
		return rv;

	/* update the related public key object */
	obj2 = cert->cert_pubkey;

	obj2->pub_data = cert->cert_data->key;
	/* We take the pub key from the cert that we will discard below */
	/* invalidate public data of the cert object so that sc_pkcs15_cert_free
	 * does not free the public key data as well (something like
	 * sc_pkcs15_pubkey_dup would have been nice here) -- Nils
	 */
	cert->cert_data->key = NULL;

	/* now that we have the cert and pub key, lets see if we can bind anything else */
	
	pkcs15_bind_related_objects(fw_data);

	return 0;
}

static void
pkcs15_add_object(struct sc_pkcs11_slot *slot,
		  struct pkcs15_any_object *obj,
		  CK_OBJECT_HANDLE_PTR pHandle)
{
	unsigned int i;
	struct pkcs15_fw_data *card_fw_data;

	if (obj == NULL
	 || (obj->base.flags & (SC_PKCS11_OBJECT_HIDDEN | SC_PKCS11_OBJECT_RECURS)))
		return;

        
	if (list_contains(&slot->objects, obj))
		return;

	if (pHandle != NULL)
		*pHandle = (CK_OBJECT_HANDLE)obj; /* cast pointer to long */

	list_append(&slot->objects, obj);
	sc_debug(context, SC_LOG_DEBUG_NORMAL, "Setting object handle of 0x%lx to 0x%lx", obj->base.handle, (CK_OBJECT_HANDLE)obj);
	obj->base.handle = (CK_OBJECT_HANDLE)obj; /* cast pointer to long */
	obj->base.flags |= SC_PKCS11_OBJECT_SEEN;
	obj->refcount++;

	/* Add related objects
	 * XXX prevent infinite recursion when a card specifies two certificates
	 * referring to each other.
	 */
	obj->base.flags |= SC_PKCS11_OBJECT_RECURS;

	switch (__p15_type(obj)) {
	case SC_PKCS15_TYPE_PRKEY_RSA:
	case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
		pkcs15_add_object(slot, (struct pkcs15_any_object *) obj->related_pubkey, NULL);
		card_fw_data = (struct pkcs15_fw_data *) slot->card->fw_data;
		for (i = 0; i < card_fw_data->num_objects; i++) {
			struct pkcs15_any_object *obj2 = card_fw_data->objects[i];
			struct pkcs15_cert_object *cert;

			if (!is_cert(obj2))
				continue;

			cert = (struct pkcs15_cert_object*) obj2;

			if ((struct pkcs15_any_object*)(cert->cert_prvkey) != obj)
				continue;

			pkcs15_add_object(slot, obj2, NULL);
		}
		break;
	case SC_PKCS15_TYPE_CERT_X509:
		pkcs15_add_object(slot, (struct pkcs15_any_object *) obj->related_pubkey, NULL);
		pkcs15_add_object(slot, (struct pkcs15_any_object *) obj->related_cert, NULL);
		break;
	}

	obj->base.flags &= ~SC_PKCS11_OBJECT_RECURS;
}

static void pkcs15_init_slot(struct sc_pkcs15_card *p15card,
		struct sc_pkcs11_slot *slot,
		struct sc_pkcs15_object *auth)
{
	struct pkcs15_slot_data *fw_data;
	struct sc_pkcs15_pin_info *pin_info = NULL;
	char tmp[64];

	pkcs15_init_token_info(p15card, &slot->token_info);
	slot->token_info.flags |= CKF_TOKEN_INITIALIZED;
	if (auth != NULL)
		slot->token_info.flags |= CKF_USER_PIN_INITIALIZED;
	if (p15card->card->reader->capabilities & SC_READER_CAP_PIN_PAD) {
		slot->token_info.flags |= CKF_PROTECTED_AUTHENTICATION_PATH;
	}

	if (p15card->card->caps & SC_CARD_CAP_RNG && p15card->card->ops->get_challenge != NULL)
		slot->token_info.flags |= CKF_RNG;

	slot->fw_data = fw_data = calloc(1, sizeof(*fw_data));
	fw_data->auth_obj = auth;

	if (auth != NULL) {
		pin_info = (struct sc_pkcs15_pin_info*) auth->data;

		if (auth->label[0]) {
			snprintf(tmp, sizeof(tmp), "%s (%s)",
				p15card->tokeninfo->label, auth->label);
		} else {
			snprintf(tmp, sizeof(tmp), "%s", p15card->tokeninfo->label);
		}
		slot->token_info.flags |= CKF_LOGIN_REQUIRED;
	} else
		snprintf(tmp, sizeof(tmp), "%s", p15card->tokeninfo->label);
	strcpy_bp(slot->token_info.label, tmp, 32);

	if (pin_info && pin_info->magic == SC_PKCS15_PIN_MAGIC) {
		slot->token_info.ulMaxPinLen = pin_info->max_length;
		slot->token_info.ulMinPinLen = pin_info->min_length;
	} else {
		/* choose reasonable defaults */
		slot->token_info.ulMaxPinLen = 8;
		slot->token_info.ulMinPinLen = 4;
	}
	if (p15card->flags & SC_PKCS15_CARD_FLAG_EMULATED)
	        slot->token_info.flags |= CKF_WRITE_PROTECTED;

	sc_debug(context, SC_LOG_DEBUG_NORMAL, "Initialized token '%s' in slot 0x%lx", tmp, slot->id);
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
	struct sc_pkcs11_slot *slot = NULL;
	int i, rv;
	int auth_count;
	int found_auth_count = 0;
	unsigned int j;

	rv = sc_pkcs15_get_objects(fw_data->p15_card,
					SC_PKCS15_TYPE_AUTH_PIN,
					auths,
					SC_PKCS15_MAX_PINS);
	if (rv < 0)
		return sc_to_cryptoki_error(rv, NULL);
	sc_debug(context, SC_LOG_DEBUG_NORMAL, "Found %d authentication objects\n", rv);
	auth_count = rv;

	rv = pkcs15_create_pkcs11_objects(fw_data,
				SC_PKCS15_TYPE_PRKEY_RSA,
				"RSA private key",
				__pkcs15_create_prkey_object);
 	if (rv < 0)
 		return sc_to_cryptoki_error(rv, NULL);

 	rv = pkcs15_create_pkcs11_objects(fw_data,
				SC_PKCS15_TYPE_PUBKEY_RSA,
				"RSA public key",
				__pkcs15_create_pubkey_object);
 	if (rv < 0)
 		return sc_to_cryptoki_error(rv, NULL);

	rv = pkcs15_create_pkcs11_objects(fw_data,
				SC_PKCS15_TYPE_PRKEY_EC,
				"EC private key",
				__pkcs15_create_prkey_object);
 	if (rv < 0)
 		return sc_to_cryptoki_error(rv, NULL);

 	rv = pkcs15_create_pkcs11_objects(fw_data,
				SC_PKCS15_TYPE_PUBKEY_EC,
				"EC public key",
				__pkcs15_create_pubkey_object);
 	if (rv < 0)
 		return sc_to_cryptoki_error(rv, NULL);


	rv = pkcs15_create_pkcs11_objects(fw_data,
				SC_PKCS15_TYPE_PRKEY_GOSTR3410,
				"GOSTR3410 private key",
				__pkcs15_create_prkey_object);
	if (rv < 0)
		return sc_to_cryptoki_error(rv, NULL);

	rv = pkcs15_create_pkcs11_objects(fw_data,
				SC_PKCS15_TYPE_PUBKEY_GOSTR3410,
				"GOSTR3410 public key",
				__pkcs15_create_pubkey_object);
	if (rv < 0)
		return sc_to_cryptoki_error(rv, NULL);

	rv = pkcs15_create_pkcs11_objects(fw_data,
				SC_PKCS15_TYPE_CERT_X509,
				"certificate",
				__pkcs15_create_cert_object);
	if (rv < 0)
		return sc_to_cryptoki_error(rv, NULL);

	rv = pkcs15_create_pkcs11_objects(fw_data,
				SC_PKCS15_TYPE_DATA_OBJECT,
				"data object",
				__pkcs15_create_data_object);
	if (rv < 0)
		return sc_to_cryptoki_error(rv, NULL);

	/* Match up related keys and certificates */
	pkcs15_bind_related_objects(fw_data);

	if (hack_enabled)
		auth_count = 1;

	for (i = 0; i < auth_count; i++) {
		struct sc_pkcs15_pin_info *pin_info = NULL;

		pin_info = (struct sc_pkcs15_pin_info*) auths[i]->data;

		/* Ignore any non-authentication PINs */
		if ((pin_info->flags & SC_PKCS15_PIN_FLAG_SO_PIN) != 0)
			continue;

		/* Ignore unblocking pins for hacked module */
		if (hack_enabled && (pin_info->flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN) != 0)
			continue;

		/* Ignore unblocking pins */
		if (!sc_pkcs11_conf.create_puk_slot)
			if (pin_info->flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN)
				continue;

		found_auth_count++;

		rv = pkcs15_create_slot(p11card, auths[i], &slot);
		if (rv != CKR_OK)
			return CKR_OK; /* no more slots available for this card */

		/* Add all objects related to this pin */
		for (j=0; j < fw_data->num_objects; j++) {
			struct pkcs15_any_object *obj = fw_data->objects[j];

			/* "Fake" objects we've generated */
			if (__p15_type(obj) == (unsigned int)-1)
				continue;
			/* Some objects have an auth_id even though they are
			 * not private. Just ignore those... */
			if (!(obj->p15_object->flags & SC_PKCS15_CO_FLAG_PRIVATE))
				continue;
			if (!sc_pkcs15_compare_id(&pin_info->auth_id, &obj->p15_object->auth_id))
				continue;

			if (is_privkey(obj)) {
				sc_debug(context, SC_LOG_DEBUG_NORMAL, "Adding private key %d to PIN %d\n", j, i);
				pkcs15_add_object(slot, obj, NULL);
			}
			else if (is_data(obj)) {
				sc_debug(context, SC_LOG_DEBUG_NORMAL, "Adding data object %d to PIN %d\n", j, i);
				pkcs15_add_object(slot, obj, NULL);
			}
			else if (is_cert(obj)) {
				sc_debug(context, SC_LOG_DEBUG_NORMAL, "Adding cert object %d to PIN %d\n", j, i);
				pkcs15_add_object(slot, obj, NULL);
			}
		}
	}

	auth_count = found_auth_count;

	/* Add all public objects to a virtual slot without pin protection.
	 * If there's only 1 pin and the hide_empty_tokens option is set,
	 * add the public objects to the slot that corresponds to that pin.
	 */
	if (!(auth_count == 1 && (sc_pkcs11_conf.hide_empty_tokens || (fw_data->p15_card->flags & SC_PKCS15_CARD_FLAG_EMULATED))))
		slot = NULL;

	/* Add all the remaining objects */
	for (j = 0; j < fw_data->num_objects; j++) {
		struct pkcs15_any_object *obj = fw_data->objects[j];
		/* We only have one pin and only the things related to it. */
		if (hack_enabled)
			break;

		if (!(obj->base.flags & SC_PKCS11_OBJECT_SEEN)) {
			sc_debug(context, SC_LOG_DEBUG_NORMAL, "%d: Object ('%s',type:%X) was not seen previously\n", j, 
					obj->p15_object->label, obj->p15_object->type);
			if (!slot) {
				rv = pkcs15_create_slot(p11card, NULL, &slot);
				if (rv != CKR_OK)
					return CKR_OK; /* no more slots available for this card */
			}
			pkcs15_add_object(slot, obj, NULL);
		}
	}

	/* FIXME Create read/write slots 
	while (slot_allocate(&slot, p11card) == CKR_OK) {
		if (!sc_pkcs11_conf.hide_empty_tokens && !(fw_data->p15_card->flags & SC_PKCS15_CARD_FLAG_EMULATED)) {
			slot->slot_info.flags |= CKF_TOKEN_PRESENT;
			pkcs15_init_token_info(fw_data->p15_card, &slot->token_info);
			strcpy_bp(slot->token_info.label, fw_data->p15_card->label, 32);
			slot->token_info.flags |= CKF_TOKEN_INITIALIZED;
		}
	}
	*/
	sc_debug(context, SC_LOG_DEBUG_NORMAL, "All tokens created\n");
	return CKR_OK;
}

static CK_RV pkcs15_release_token(struct sc_pkcs11_card *p11card, void *fw_token)
{
	unlock_card((struct pkcs15_fw_data *) p11card->fw_data);
	free(fw_token);
	return CKR_OK;
}

static CK_RV pkcs15_login(struct sc_pkcs11_slot *slot,
			  CK_USER_TYPE userType,
			  CK_CHAR_PTR pPin,
			  CK_ULONG ulPinLen)
{
	int rc;
	struct sc_pkcs11_card *p11card = slot->card;
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	struct sc_pkcs15_card *p15card = fw_data->p15_card;
	struct sc_pkcs15_object *auth_object;
	struct sc_pkcs15_pin_info *pin_info;

	switch (userType) {
	case CKU_USER:
		auth_object = slot_data_auth(slot->fw_data);
		if (auth_object == NULL)
			return CKR_USER_PIN_NOT_INITIALIZED;
		break;
	case CKU_SO:
		/* A card with no SO PIN is treated as if no SO login
		 * is required */
		rc = sc_pkcs15_find_so_pin(p15card, &auth_object);

		/* If there's no SO PIN on the card, silently
		 * accept any PIN, and lock the card if required */
		if (rc == SC_ERROR_OBJECT_NOT_FOUND)   {
			rc = 0;
			if (sc_pkcs11_conf.lock_login)
				rc = lock_card(fw_data);

			if (sc_pkcs11_conf.pin_unblock_style == SC_PKCS11_PIN_UNBLOCK_SO_LOGGED_INITPIN)   {
				if (ulPinLen && ulPinLen < sizeof(fw_data->user_puk))   {
					memcpy(fw_data->user_puk, pPin, ulPinLen);
					fw_data->user_puk_len = ulPinLen;
				}
			}

			sc_debug(context, SC_LOG_DEBUG_NORMAL, "No SOPIN found; returns %d", rc);
			return sc_to_cryptoki_error(rc, "C_Login");
		}
		else if (rc < 0)   {
			return sc_to_cryptoki_error(rc, "C_Login");
		}

		break;
	case CKU_CONTEXT_SPECIFIC:
		/*
		 * A session should already be open for user or SO 
		 * All we need to do is authenticate to the card
		 * using the correct auth_object. 
		 * TODO: handle the CK_SO case
		 */
		sc_debug(context, SC_LOG_DEBUG_NORMAL, "context specific login %d",
				slot->login_user);
		if (slot->login_user == CKU_USER) {
			auth_object = slot_data_auth(slot->fw_data);
			if (auth_object == NULL)
				return CKR_USER_PIN_NOT_INITIALIZED;
			break;
		}
		/* TODO looks like this was never executed,
		 * And even if it was, why the lock as a session 
		 * should already be open and the card locked. 
		 */
		/* For a while, used only to unblock User PIN. */
		rc = 0;
		if (sc_pkcs11_conf.lock_login)
		       	rc = lock_card(fw_data);
#if 0
		/* TODO: Look for pkcs15 auth object with 'unblockingPin' flag activated.
		 * If exists, do verification of PIN (in fact PUK). */
		if (sc_pkcs11_conf.pin_unblock_style == SC_PKCS11_PIN_UNBLOCK_SCONTEXT_SETPIN)   {
			if (ulPinLen && ulPinLen < sizeof(fw_data->user_puk))   {
				memcpy(fw_data->user_puk, pPin, ulPinLen);
				fw_data->user_puk_len = ulPinLen;
			}
		}
#endif
		sc_debug(context, SC_LOG_DEBUG_NORMAL, "context specific login returns %d", rc);
		return sc_to_cryptoki_error(rc, "C_Login");
	default:
		return CKR_USER_TYPE_INVALID;
	}
	pin_info = (struct sc_pkcs15_pin_info *) auth_object->data;

	if (p11card->card->reader->capabilities & SC_READER_CAP_PIN_PAD) {
		/* pPin should be NULL in case of a pin pad reader, but
		 * some apps (e.g. older Netscapes) don't know about it.
		 * So we don't require that pPin == NULL, but set it to
		 * NULL ourselves. This way, you can supply an empty (if
		 * possible) or fake PIN if an application asks a PIN).
		 */
		/* But we want to be able to specify a PIN on the command
		 * line (e.g. for the test scripts). So we don't do anything
		 * here - this gives the user the choice of entering
		 * an empty pin (which makes us use the pin pad) or
		 * a valid pin (which is processed normally). --okir */
		if (ulPinLen == 0)
			pPin = NULL;
	} else {
		/*
		 * If PIN is out of range,
		 * it cannot be correct.
		 */
		if (ulPinLen < pin_info->min_length ||
		    ulPinLen > pin_info->max_length)
			return CKR_PIN_INCORRECT;
	}


	/* By default, we make the reader resource manager keep other
	 * processes from accessing the card while we're logged in.
	 * Otherwise an attacker could perform some crypto operation
	 * after we've authenticated with the card */

	/* Context specific login is not real login but only a
	 * reassertion of the PIN to the card. 
	 * And we don't want to do any extra operations to the card
	 * that could invalidate the assertion of the pin
	 * before the crypto operation that requires the assertion
	 */
	if (userType != CKU_CONTEXT_SPECIFIC) {
	if (sc_pkcs11_conf.lock_login && (rc = lock_card(fw_data)) < 0)
		return sc_to_cryptoki_error(rc, "C_Login");
	}

	rc = sc_pkcs15_verify_pin(p15card, auth_object, pPin, ulPinLen);
	sc_debug(context, SC_LOG_DEBUG_NORMAL, "PKCS15 verify PIN returned %d", rc);	

	if (rc != SC_SUCCESS)
		return sc_to_cryptoki_error(rc, "C_Login");

	if (userType == CKU_USER)   {
		sc_pkcs15_object_t *p15_obj = p15card->obj_list;
		sc_pkcs15_search_key_t sk;

		sc_debug(context, SC_LOG_DEBUG_NORMAL, "Check if pkcs15 object list can be completed.");

		/* Ensure non empty list */
		if (p15_obj == NULL)
			return CKR_OK;

		/* Select last object in list */
		while(p15_obj->next)
			p15_obj = p15_obj->next;

		/* Trigger enumeration of EF.XXX files */
		memset(&sk, 0, sizeof(sk));
		sk.class_mask = SC_PKCS15_SEARCH_CLASS_PRKEY | SC_PKCS15_SEARCH_CLASS_PUBKEY |
				SC_PKCS15_SEARCH_CLASS_CERT  | SC_PKCS15_SEARCH_CLASS_DATA;
		sc_pkcs15_search_objects(p15card, &sk, NULL, 0);

		/* Iterate over newly discovered objects */
		while(p15_obj->next) {
			struct pkcs15_any_object *fw_obj;

			p15_obj = p15_obj->next;

			if (!sc_pkcs15_compare_id(&pin_info->auth_id, &p15_obj->auth_id))
				continue;

			switch (p15_obj->type & SC_PKCS15_TYPE_CLASS_MASK) {
			case SC_PKCS15_TYPE_PRKEY:
				__pkcs15_create_prkey_object(fw_data, p15_obj, &fw_obj); break;
			case SC_PKCS15_TYPE_PUBKEY:
				__pkcs15_create_pubkey_object(fw_data, p15_obj, &fw_obj); break;
			case SC_PKCS15_TYPE_CERT:
				__pkcs15_create_cert_object(fw_data, p15_obj, &fw_obj); break;
			case SC_PKCS15_TYPE_DATA_OBJECT:
				__pkcs15_create_data_object(fw_data, p15_obj, &fw_obj); break;
			default: continue;
			}

			sc_debug(context, SC_LOG_DEBUG_NORMAL, "new object found: type=0x%03X", p15_obj->type);
			pkcs15_add_object(slot, fw_obj, NULL);
		}
	}

	return CKR_OK;
}

static CK_RV pkcs15_logout(struct sc_pkcs11_card *p11card, void *fw_token)
{
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	CK_RV ret = CKR_OK;
	int rc;
       
	memset(fw_data->user_puk, 0, sizeof(fw_data->user_puk));
	fw_data->user_puk_len = 0;

	sc_pkcs15_pincache_clear(fw_data->p15_card);

	rc = sc_logout(fw_data->p15_card->card);
	if (rc != SC_SUCCESS)
		ret = sc_to_cryptoki_error(rc, "C_Logout");

	if (sc_pkcs11_conf.lock_login) {
		rc = unlock_card(fw_data);
		if (rc != SC_SUCCESS)
			ret = sc_to_cryptoki_error(rc, "C_Logout");
	}

	return ret;
}

static CK_RV pkcs15_change_pin(struct sc_pkcs11_card *p11card,
			  void *fw_token, int login_user,
			  CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen,
			  CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	int rc;
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	struct sc_pkcs15_pin_info *pin_info;
	struct sc_pkcs15_object *pin_obj;

	if (!(pin_obj = slot_data_auth(fw_token)))
		return CKR_USER_PIN_NOT_INITIALIZED;

	if (!(pin_info = slot_data_pin_info(fw_token)))
		return CKR_USER_PIN_NOT_INITIALIZED;

	if (p11card->card->reader->capabilities & SC_READER_CAP_PIN_PAD) {
		/* pPin should be NULL in case of a pin pad reader, but
		 * some apps (e.g. older Netscapes) don't know about it.
		 * So we don't require that pPin == NULL, but set it to
		 * NULL ourselves. This way, you can supply an empty (if
		 * possible) or fake PIN if an application asks a PIN).
		 */
		pOldPin = pNewPin = NULL;
		ulOldLen = ulNewLen = 0;
	} 
	else if (ulNewLen < pin_info->min_length || ulNewLen > pin_info->max_length)  {
		return CKR_PIN_LEN_RANGE;
	}

	if (login_user < 0)   {
		if (sc_pkcs11_conf.pin_unblock_style != SC_PKCS11_PIN_UNBLOCK_UNLOGGED_SETPIN)   {
			sc_debug(context, SC_LOG_DEBUG_NORMAL, "PIN unlock is not allowed in unlogged session");
			return CKR_FUNCTION_NOT_SUPPORTED;
		}
		rc = sc_pkcs15_unblock_pin(fw_data->p15_card, pin_obj, pOldPin, ulOldLen, pNewPin, ulNewLen);
	}
	else if (login_user == CKU_CONTEXT_SPECIFIC)   {
		if (sc_pkcs11_conf.pin_unblock_style != SC_PKCS11_PIN_UNBLOCK_SCONTEXT_SETPIN)   {
			sc_debug(context, SC_LOG_DEBUG_NORMAL, "PIN unlock is not allowed with CKU_CONTEXT_SPECIFIC login");
			return CKR_FUNCTION_NOT_SUPPORTED;
		}
		rc = sc_pkcs15_unblock_pin(fw_data->p15_card, pin_obj, pOldPin, ulOldLen, pNewPin, ulNewLen);
	}
	else if (login_user == CKU_USER)   {
		rc = sc_pkcs15_change_pin(fw_data->p15_card, pin_obj, pOldPin, ulOldLen, pNewPin, ulNewLen);
	}
	else   {
		sc_debug(context, SC_LOG_DEBUG_NORMAL, "cannot change PIN: non supported login type: %i", login_user);
		return CKR_FUNCTION_NOT_SUPPORTED;
	}

	sc_debug(context, SC_LOG_DEBUG_NORMAL, "PIN change returns %d\n", rc);
	return sc_to_cryptoki_error(rc, "C_SetPIN");
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
	struct sc_pkcs15_pin_info *pin_info;
	int			rc;

	sc_debug(context, SC_LOG_DEBUG_NORMAL, "pkcs15 init PIN: pin %p:%d\n", pPin, ulPinLen);

	pin_info = slot_data_pin_info(slot->fw_data);
	if (pin_info && sc_pkcs11_conf.pin_unblock_style == SC_PKCS11_PIN_UNBLOCK_SO_LOGGED_INITPIN)   {
		auth_obj = slot_data_auth(slot->fw_data);
		if (fw_data->user_puk_len)   {
			rc = sc_pkcs15_unblock_pin(fw_data->p15_card, auth_obj, 
					fw_data->user_puk, fw_data->user_puk_len, pPin, ulPinLen);
		}
		else   {
#if 0
			/* TODO: Actually sc_pkcs15_unblock_pin() do not accepts zero length value as a PUK argument.
			 * It's usefull for the cards that do not supports modes 00 and 01 
			 * of ISO 'RESET RETRY COUNTER' command. */
			rc = sc_pkcs15_unblock_pin(fw_data->p15_card, auth_obj, NULL, 0, pPin, ulPinLen);
#else
			return sc_to_cryptoki_error(SC_ERROR_NOT_SUPPORTED, "C_InitPIN");
#endif
		}

		return sc_to_cryptoki_error(rc, "C_InitPIN");
	}

	rc = sc_lock(p11card->card);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, "C_InitPIN");

	rc = sc_pkcs15init_bind(p11card->card, "pkcs15", NULL, &profile);
	if (rc < 0) {
		sc_unlock(p11card->card);
		return sc_to_cryptoki_error(rc, "C_InitPIN");
	}

	memset(&args, 0, sizeof(args));
	args.label = "User PIN";
	args.pin = pPin;
	args.pin_len = ulPinLen;
	rc = sc_pkcs15init_store_pin(fw_data->p15_card, profile, &args);

	sc_pkcs15init_unbind(profile);
	sc_unlock(p11card->card);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, "C_InitPIN");

	rc = sc_pkcs15_find_pin_by_auth_id(fw_data->p15_card, &args.auth_id, &auth_obj);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, "C_InitPIN");

	/* Re-initialize the slot */
	free(slot->fw_data);
	pkcs15_init_slot(fw_data->p15_card, slot, auth_obj);

	pin_info = (sc_pkcs15_pin_info_t *) auth_obj->data;
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
	struct sc_pkcs15_prkey_ec  *ec;
	int			rc, rv;
	char label[SC_PKCS15_MAX_LABEL_SIZE];

	memset(&args, 0, sizeof(args));

	/* See if the "slot" is pin protected. If so, get the
	 * PIN id */
	if ((pin = slot_data_pin_info(slot->fw_data)) != NULL)
		args.auth_id = pin->auth_id;

	/* Get the key type */
	rv = attr_find(pTemplate, ulCount, CKA_KEY_TYPE, &key_type, NULL);
	if (rv != CKR_OK)
		return rv;
	switch (key_type) {
		case CKK_RSA:
			args.key.algorithm = SC_ALGORITHM_RSA;
			rsa = &args.key.u.rsa;
			break;
		case CKK_EC:
			args.key.algorithm = SC_ALGORITHM_EC;
			ec = &args.key.u.ec;
			/* TODO: -DEE Do not have PKCS15 card with EC to test this */
			/* fall through */
		default:
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}


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
			args.label = set_cka_label(attr, label);
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
		rv = sc_to_cryptoki_error(rc, "C_CreateObject");
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
	CK_KEY_TYPE	key_type;
	struct sc_pkcs15_pubkey_rsa *rsa;
	int rc, rv;
	char label[SC_PKCS15_MAX_LABEL_SIZE];

	memset(&args, 0, sizeof(args));

	/* See if the "slot" is pin protected. If so, get the
	 * PIN id */
	if ((pin = slot_data_pin_info(slot->fw_data)) != NULL)
		args.auth_id = pin->auth_id;

	/* Get the key type */
	rv = attr_find(pTemplate, ulCount, CKA_KEY_TYPE, &key_type, NULL);
	if (rv != CKR_OK)
		return rv;
	switch (key_type) {
		case CKK_RSA:
			args.key.algorithm = SC_ALGORITHM_RSA;
			rsa = &args.key.u.rsa;
			break;
		case CKK_EC:
			/* TODO: -DEE Do not have real pkcs15 card with EC */
			/* fall through */
		default:
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

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
			args.label = set_cka_label(attr, label);
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
		rv = sc_to_cryptoki_error(rc, "C_CreateObject");
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
	char label[SC_PKCS15_MAX_LABEL_SIZE];

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
			args.label = set_cka_label(attr, label);
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
		rv = sc_to_cryptoki_error(rc, "C_CreateObject");
		goto out;
	}
	/* Create a new pkcs11 object for it */
	__pkcs15_create_cert_object(fw_data, cert_obj, &cert_any_obj);
	pkcs15_add_object(slot, cert_any_obj, phObject);

	rv = CKR_OK;

out:	return rv;
}

static CK_RV pkcs15_create_data(struct sc_pkcs11_card *p11card,
		struct sc_pkcs11_slot *slot,
		struct sc_profile *profile,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject)
{
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	struct sc_pkcs15init_dataargs args;
	struct pkcs15_any_object *data_any_obj;
	struct sc_pkcs15_object	*data_obj;
	struct sc_pkcs15_pin_info *pin;
	CK_BBOOL		bValue;
	int			rc, rv;
	char label[SC_PKCS15_MAX_LABEL_SIZE];

	memset(&args, 0, sizeof(args));
	args.app_oid.value[0] = -1;

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
				pin = slot_data_pin_info(slot->fw_data);
				if (pin == NULL) {
					rv = CKR_TEMPLATE_INCOMPLETE;
					goto out;
				}
				args.auth_id = pin->auth_id;
			}
			break;
		case CKA_LABEL:
			args.label = set_cka_label(attr, label);
			break;
		case CKA_ID:
			args.id.len = sizeof(args.id.value);
			rv = attr_extract(attr, args.id.value, &args.id.len);
			if (rv != CKR_OK)
				goto out;
			break;
		case CKA_APPLICATION:
			args.app_label = (char *) attr->pValue;
			break;
		case CKA_OBJECT_ID:
			rv = attr_extract(attr, args.app_oid.value, NULL);
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

	rc = sc_pkcs15init_store_data_object(fw_data->p15_card, profile, &args, &data_obj);
	if (rc < 0) {
		rv = sc_to_cryptoki_error(rc, "C_CreateObject");
		goto out;
	}
	/* Create a new pkcs11 object for it */
	__pkcs15_create_data_object(fw_data, data_obj, &data_any_obj);
	pkcs15_add_object(slot, data_any_obj, phObject);

	rv = CKR_OK;

out:	return rv;
}

static CK_RV pkcs15_create_object(struct sc_pkcs11_card *p11card,
		struct sc_pkcs11_slot *slot,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject)
{
	struct sc_profile *profile = NULL;
	CK_OBJECT_CLASS	_class;
	int rv, rc;

	rv = attr_find(pTemplate, ulCount, CKA_CLASS, &_class, NULL);
	if (rv != CKR_OK)
		return rv;

	rc = sc_lock(p11card->card);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, "C_CreateObject");

	/* Bind the profile */
	rc = sc_pkcs15init_bind(p11card->card, "pkcs15", NULL, &profile);
	if (rc < 0) {
		sc_unlock(p11card->card);
		return sc_to_cryptoki_error(rc, "C_CreateObject");
	}

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
	case CKO_DATA:
		rv = pkcs15_create_data(p11card, slot, profile,
				pTemplate, ulCount, phObject);
		break;
	default:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}

	sc_pkcs15init_unbind(profile);
	sc_unlock(p11card->card);

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
			*x509_usage |= SC_PKCS15INIT_X509_DIGITAL_SIGNATURE;
		if (typ == CKA_UNWRAP && *val)
			*x509_usage |= SC_PKCS15INIT_X509_KEY_ENCIPHERMENT;
		if (typ == CKA_DECRYPT && *val)
			*x509_usage |= SC_PKCS15INIT_X509_DATA_ENCIPHERMENT;
		if (typ == CKA_DERIVE && *val)
			*x509_usage |= SC_PKCS15INIT_X509_KEY_AGREEMENT;
		if (typ == CKA_VERIFY || typ == CKA_WRAP || typ == CKA_ENCRYPT) {
			sc_debug(context, SC_LOG_DEBUG_NORMAL, "get_X509_usage_privk(): invalid typ = 0x%0x\n", typ);
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
			*x509_usage |= SC_PKCS15INIT_X509_DIGITAL_SIGNATURE;
		if (typ == CKA_WRAP && *val)
			*x509_usage |= SC_PKCS15INIT_X509_KEY_ENCIPHERMENT;
		if (typ == CKA_ENCRYPT && *val)
			*x509_usage |= SC_PKCS15INIT_X509_DATA_ENCIPHERMENT;
		if (typ == CKA_DERIVE && *val)
			*x509_usage |= SC_PKCS15INIT_X509_KEY_AGREEMENT;
		if (typ == CKA_SIGN || typ == CKA_UNWRAP || typ == CKA_DECRYPT) {
			sc_debug(context, SC_LOG_DEBUG_NORMAL, "get_X509_usage_pubk(): invalid typ = 0x%0x\n", typ);
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}
	return CKR_OK;
}

static CK_RV
set_gost_params(struct sc_pkcs15init_prkeyargs *prkey_args,
		struct sc_pkcs15init_pubkeyargs *pubkey_args,
		CK_ATTRIBUTE_PTR pPubTpl, CK_ULONG ulPubCnt,
		CK_ATTRIBUTE_PTR pPrivTpl, CK_ULONG ulPrivCnt)
{
	CK_BYTE gost_params_oid[GOST_PARAMS_OID_SIZE];
	size_t len, i;
	CK_RV rv;

	len = GOST_PARAMS_OID_SIZE;
	rv = attr_find2(pPubTpl, ulPubCnt, pPrivTpl, ulPrivCnt, CKA_GOSTR3410_PARAMS,
			&gost_params_oid, &len);
	if (rv == CKR_OK) {
		if (len != GOST_PARAMS_OID_SIZE)
			return CKR_ATTRIBUTE_VALUE_INVALID;
		for (i = 0; i < sizeof(gostr3410_param_oid)
				/sizeof(gostr3410_param_oid[0]); ++i) {
			if (!memcmp(gost_params_oid, gostr3410_param_oid[i].oid, len)) {
				prkey_args->gost_params.gostr3410 =
					gostr3410_param_oid[i].param;
				pubkey_args->gost_params.gostr3410 =
					gostr3410_param_oid[i].param;
				break;
			}
		}
		if (i != sizeof(gostr3410_param_oid)/sizeof(gostr3410_param_oid[0]))
			return CKR_OK;
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}
	return CKR_OK;
}

/* FIXME: check for the public exponent in public key template and use this value */
static CK_RV pkcs15_gen_keypair(struct sc_pkcs11_card *p11card,
			struct sc_pkcs11_slot *slot,
			CK_MECHANISM_PTR pMechanism,
			CK_ATTRIBUTE_PTR pPubTpl, CK_ULONG ulPubCnt,
			CK_ATTRIBUTE_PTR pPrivTpl, CK_ULONG ulPrivCnt,
			CK_OBJECT_HANDLE_PTR phPubKey, CK_OBJECT_HANDLE_PTR phPrivKey)                /* gets priv. key handle */
{
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_pin_info *pin;
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	struct sc_pkcs15init_keygen_args keygen_args;
	struct sc_pkcs15init_pubkeyargs pub_args;
	struct sc_pkcs15_object	 *priv_key_obj;
	struct sc_pkcs15_object	 *pub_key_obj;
	struct pkcs15_any_object *priv_any_obj;
	struct pkcs15_any_object *pub_any_obj;
	struct sc_pkcs15_id id;
	size_t		len;
	CK_KEY_TYPE	keytype;
	CK_ULONG	keybits;
	char		pub_label[SC_PKCS15_MAX_LABEL_SIZE];
	char		priv_label[SC_PKCS15_MAX_LABEL_SIZE];
	int		rc, rv = CKR_OK;

	sc_debug(context, SC_LOG_DEBUG_NORMAL, "Keypair generation, mech = 0x%0x\n", pMechanism->mechanism);

	if (pMechanism->mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN
			&& pMechanism->mechanism != CKM_GOSTR3410_KEY_PAIR_GEN)
		return CKR_MECHANISM_INVALID;

	rc = sc_lock(p11card->card);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, "C_GenerateKeyPair");

	rc = sc_pkcs15init_bind(p11card->card, "pkcs15", NULL, &profile);
	if (rc < 0) {
		sc_unlock(p11card->card);
		return sc_to_cryptoki_error(rc, "C_GenerateKeyPair");
	}

	memset(&keygen_args, 0, sizeof(keygen_args));
	memset(&pub_args, 0, sizeof(pub_args));

	/* 1. Convert the pkcs11 attributes to pkcs15init args */

	if ((pin = slot_data_pin_info(slot->fw_data)) != NULL)
		keygen_args.prkey_args.auth_id = pub_args.auth_id = pin->auth_id;

	rv = attr_find2(pPubTpl, ulPubCnt, pPrivTpl, ulPrivCnt, CKA_KEY_TYPE,
		&keytype, NULL);
	if (rv != CKR_OK && pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN)
		keytype = CKK_RSA;
	else if (rv != CKR_OK)
		goto kpgen_done;
	if (keytype == CKK_GOSTR3410)
	{
		keygen_args.prkey_args.key.algorithm = SC_ALGORITHM_GOSTR3410;
		pub_args.key.algorithm               = SC_ALGORITHM_GOSTR3410;
		set_gost_params(&keygen_args.prkey_args, &pub_args,
				pPubTpl, ulPubCnt, pPrivTpl, ulPrivCnt);
	}
	else if (keytype == CKK_RSA)
	{
		/* default value (CKA_KEY_TYPE isn't set) or CKK_RSA is set */
		keygen_args.prkey_args.key.algorithm = SC_ALGORITHM_RSA;
		pub_args.key.algorithm               = SC_ALGORITHM_RSA;
	}
	else
	{
		/* CKA_KEY_TYPE is set, but keytype isn't correct */
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto kpgen_done;
	}
	if (keytype == CKK_GOSTR3410)
		keybits = SC_PKCS15_GOSTR3410_KEYSIZE;
	else if (keytype == CKK_RSA)
	{
		rv = attr_find2(pPubTpl, ulPubCnt, pPrivTpl, ulPrivCnt,	CKA_MODULUS_BITS,
			&keybits, NULL);
		if (rv != CKR_OK)
			keybits = 1024; /* Default key size */
		/* TODO: check allowed values of keybits */
	}

	id.len = SC_PKCS15_MAX_ID_SIZE;
	rv = attr_find2(pPubTpl, ulPubCnt, pPrivTpl, ulPrivCnt,	CKA_ID,
		&id.value, &id.len);
	if (rv == CKR_OK)
		keygen_args.prkey_args.id = pub_args.id = id;

	len = sizeof(priv_label) - 1;
	rv = attr_find(pPrivTpl, ulPrivCnt, CKA_LABEL, priv_label, &len);
	if (rv == CKR_OK) {
		priv_label[len] = '\0';
		keygen_args.prkey_args.label = priv_label;
	}
	len = sizeof(pub_label) - 1;
	rv = attr_find(pPubTpl, ulPubCnt, CKA_LABEL, pub_label, &len);
	if (rv == CKR_OK) {
		pub_label[len] = '\0';
		keygen_args.pubkey_label = pub_label;
		pub_args.label = pub_label;
	}

	rv = get_X509_usage_privk(pPrivTpl, ulPrivCnt,
	    	&keygen_args.prkey_args.x509_usage);
	if (rv == CKR_OK)
		rv = get_X509_usage_pubk(pPubTpl, ulPubCnt,
			&keygen_args.prkey_args.x509_usage);
	if (rv != CKR_OK)
		goto kpgen_done;
	pub_args.x509_usage = keygen_args.prkey_args.x509_usage;

	/* 3.a Try on-card key pair generation */

	sc_pkcs15init_set_p15card(profile, fw_data->p15_card);

	sc_debug(context, SC_LOG_DEBUG_NORMAL, "Try on-card key pair generation");
	rc = sc_pkcs15init_generate_key(fw_data->p15_card, profile,
		&keygen_args, keybits, &priv_key_obj);
	if (rc >= 0) {
		id = ((struct sc_pkcs15_prkey_info *) priv_key_obj->data)->id;
		rc = sc_pkcs15_find_pubkey_by_id(fw_data->p15_card, &id, &pub_key_obj);
		if (rc != 0) {
			sc_debug(context, SC_LOG_DEBUG_NORMAL, "sc_pkcs15_find_pubkey_by_id returned %d\n", rc);
			rv = sc_to_cryptoki_error(rc, "C_GenerateKeyPair");
			goto kpgen_done;
		}
	}
	else if (rc != SC_ERROR_NOT_SUPPORTED) {
		sc_debug(context, SC_LOG_DEBUG_NORMAL, "sc_pkcs15init_generate_key returned %d\n", rc);
		rv = sc_to_cryptoki_error(rc, "C_GenerateKeyPair");
		goto kpgen_done;
	}

	/* 4. Create new pkcs11 public and private key object */

	rc = __pkcs15_create_prkey_object(fw_data, priv_key_obj, &priv_any_obj);
	if (rc == 0)
		rc = __pkcs15_create_pubkey_object(fw_data, pub_key_obj, &pub_any_obj);
	if (rc != 0) {
		sc_debug(context, SC_LOG_DEBUG_NORMAL, "__pkcs15_create_pr/pubkey_object returned %d\n", rc);
		rv = sc_to_cryptoki_error(rc, "C_GenerateKeyPair");
		goto kpgen_done;
	}
	pkcs15_add_object(slot, priv_any_obj, phPrivKey);
	pkcs15_add_object(slot, pub_any_obj, phPubKey);
	((struct pkcs15_prkey_object *) priv_any_obj)->prv_pubkey =
		(struct pkcs15_pubkey_object *)pub_any_obj;

kpgen_done:
	sc_pkcs15init_unbind(profile);
	sc_unlock(p11card->card);

	return rv;
}
#endif

static CK_RV pkcs15_any_destroy(struct sc_pkcs11_session *session, void *object)
{
	struct pkcs15_data_object *obj = (struct pkcs15_data_object*) object;
	struct pkcs15_any_object *any_obj = (struct pkcs15_any_object*) object;
	struct sc_pkcs11_card *card = session->slot->card;
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) card->fw_data;
	struct sc_profile *profile = NULL;
	int rv;

	rv = sc_lock(card->card);
	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_DestroyObject");

	/* Bind the profile */
	rv = sc_pkcs15init_bind(card->card, "pkcs15", NULL, &profile);
	if (rv < 0) {
		sc_unlock(card->card);
		return sc_to_cryptoki_error(rv, "C_DestroyObject");
	}

	/* Delete object in smartcard */
	rv = sc_pkcs15init_delete_object(fw_data->p15_card, profile, obj->base.p15_object);
	if (rv >= 0) {
		/* Oppose to pkcs15_add_object */
		--any_obj->refcount; /* correct refcont */
		list_delete(&session->slot->objects, any_obj);
		/* Delete object in pkcs15 */
		rv = __pkcs15_delete_object(fw_data, any_obj);
	}

	sc_pkcs15init_unbind(profile);
	sc_unlock(card->card);

	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_DestroyObject");

	return CKR_OK;
}


static CK_RV pkcs15_get_random(struct sc_pkcs11_card *p11card,
				CK_BYTE_PTR p, CK_ULONG len)
{
	int rc;
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	struct sc_card *card = fw_data->p15_card->card;

	rc = sc_get_challenge(card, p, (size_t)len);
	return sc_to_cryptoki_error(rc, "C_GenerateRandom");
}

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
	NULL,
	NULL,
#endif
	pkcs15_get_random
};

static CK_RV pkcs15_set_attrib(struct sc_pkcs11_session *session,
                               struct sc_pkcs15_object *p15_object,
                               CK_ATTRIBUTE_PTR attr)
{
#ifndef USE_PKCS15_INIT
	return CKR_FUNCTION_NOT_SUPPORTED;
#else
	struct sc_profile *profile = NULL;
	struct sc_pkcs11_card *p11card = session->slot->card;
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) p11card->fw_data;
	struct sc_pkcs15_id id;
	int rc = 0;
	CK_RV rv = CKR_OK;

	rc = sc_lock(p11card->card);
	if (rc < 0)
		return sc_to_cryptoki_error(rc, "C_SetAttributeValue");

	rc = sc_pkcs15init_bind(p11card->card, "pkcs15", NULL, &profile);
	if (rc < 0) {
		sc_unlock(p11card->card);
		return sc_to_cryptoki_error(rc, "C_SetAttributeValue");
	}

	switch(attr->type) {
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

	rv = sc_to_cryptoki_error(rc, "C_SetAttributeValue");

set_attr_done:
	sc_pkcs15init_unbind(profile);
	sc_unlock(p11card->card);
	
	return rv;
#endif
}

/*
 * PKCS#15 Certificate Object
 */

static void pkcs15_cert_release(void *obj)
{
	struct pkcs15_cert_object *cert = (struct pkcs15_cert_object *) obj;
	struct sc_pkcs15_cert      *cert_data = cert->cert_data;

	if (__pkcs15_release_object((struct pkcs15_any_object *) obj) == 0) {
		if (cert_data) /* may never have been read */
			sc_pkcs15_free_certificate(cert_data);
	}
}

static CK_RV pkcs15_cert_set_attribute(struct sc_pkcs11_session *session,
                               void *object,
                               CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_cert_object *cert = (struct pkcs15_cert_object*) object;
	return pkcs15_set_attrib(session, cert->base.p15_object, attr);
}

static CK_RV pkcs15_cert_get_attribute(struct sc_pkcs11_session *session,
				void *object,
				CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_cert_object *cert = (struct pkcs15_cert_object*) object;
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) session->slot->card->fw_data;
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
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue =
			(cert->base.p15_object->flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0;
		break;
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
		if (cert->cert_info->authority 
				&& sc_pkcs11_conf.zero_ckaid_for_ca_certs) {
			check_attribute_buffer(attr, 1);
			*(unsigned char*)attr->pValue = 0;
		} else {
			check_attribute_buffer(attr, cert->cert_info->id.len);
			memcpy(attr->pValue, cert->cert_info->id.value, cert->cert_info->id.len);
		}
		break;
	case CKA_TRUSTED:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = cert->cert_info->authority ? TRUE : FALSE;
		break;
	case CKA_VALUE:
		if (check_cert_data_read(fw_data, cert) != 0) {
			attr->ulValueLen = 0;
			return CKR_OK;
		}
		check_attribute_buffer(attr, cert->cert_data->data_len);
		memcpy(attr->pValue, cert->cert_data->data, cert->cert_data->data_len);
		break;
	case CKA_SERIAL_NUMBER:
		if (check_cert_data_read(fw_data, cert) != 0) {
			attr->ulValueLen = 0;
			return CKR_OK;
		}
		check_attribute_buffer(attr, cert->cert_data->serial_len);
		memcpy(attr->pValue, cert->cert_data->serial, cert->cert_data->serial_len);
		break;
	case CKA_SUBJECT:
		if (check_cert_data_read(fw_data, cert) != 0) {
			attr->ulValueLen = 0;
			return CKR_OK;
		}
		return asn1_sequence_wrapper(cert->cert_data->subject,
		                             cert->cert_data->subject_len, attr);
	case CKA_ISSUER:
		if (check_cert_data_read(fw_data, cert) != 0) {
			attr->ulValueLen = 0;
			return CKR_OK;
		}
		return asn1_sequence_wrapper(cert->cert_data->issuer,
				 cert->cert_data->issuer_len, attr);
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
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) session->slot->card->fw_data;
	u8	*data;
	size_t	len;

	switch (attr->type) {
	/* Check the issuer. Some pkcs11 callers (i.e. netscape) will pass
	 * in the ASN.1 encoded SEQUENCE OF SET ... while OpenSC just
	 * keeps the SET in the issuer field. */
	case CKA_ISSUER:
		if (check_cert_data_read(fw_data, cert) != 0)
			break;
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
	pkcs15_any_destroy,
	NULL,
	NULL,
	NULL,
	NULL
};

/*
 * PKCS#15 Private Key Object
 */
static void pkcs15_prkey_release(void *object)
{
	__pkcs15_release_object((struct pkcs15_any_object *) object);
}

static CK_RV pkcs15_prkey_set_attribute(struct sc_pkcs11_session *session,
                               void *object,
                               CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_prkey_object *prkey = (struct pkcs15_prkey_object*) object;
	return pkcs15_set_attrib(session, prkey->base.p15_object, attr);
}

static CK_RV pkcs15_prkey_get_attribute(struct sc_pkcs11_session *session,
				void *object,
				CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_prkey_object *prkey = (struct pkcs15_prkey_object*) object;
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) session->slot->card->fw_data;
	struct sc_pkcs15_pubkey *key = NULL;
	unsigned int usage;
	size_t len;

	/* PKCS#11 requires us to supply CKA_MODULUS for private keys,
	 * although that is not generally available from a smart card
	 * (the key is supposed to be safely locked away after all).
	 *
	 * To work around this, we hope that we either have an associated
	 * public key, or we try to find a certificate with the
	 * corresponding public key.
	 *
	 * Note: We do the same thing for CKA_PUBLIC_EXPONENT as some
	 *       applications assume they can get that from the private
	 *       key, something PKCS#11 doesn't guarantee.
	 */
	if ((attr->type == CKA_MODULUS) || (attr->type == CKA_PUBLIC_EXPONENT) ||
		((attr->type == CKA_MODULUS_BITS) && (prkey->prv_p15obj->type == SC_PKCS15_TYPE_PRKEY_EC)) || 
		(attr->type == CKA_ECDSA_PARAMS)) {
		/* First see if we have a associated public key */
		if (prkey->prv_pubkey && prkey->prv_pubkey->pub_data)
			key = prkey->prv_pubkey->pub_data;
		else {
			/* Try to find a certificate with the public key */
			unsigned int i;

			for (i = 0; i < fw_data->num_objects; i++) {
				struct pkcs15_any_object *obj = fw_data->objects[i];
				struct pkcs15_cert_object *cert;

				if (!is_cert(obj))
					continue;

				cert = (struct pkcs15_cert_object*) obj;

				if (cert->cert_prvkey != prkey)
					continue;

				if (check_cert_data_read(fw_data, cert) == 0)
					key = cert->cert_pubkey->pub_data;
			}
		}
	}

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
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = TRUE;
		break;
        case CKA_ALWAYS_AUTHENTICATE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = prkey->prv_p15obj->user_consent;
		break;
	case CKA_PRIVATE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = (prkey->prv_p15obj->flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0;
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
		switch (prkey->prv_p15obj->type) {
			case SC_PKCS15_TYPE_PRKEY_RSA:
				*(CK_KEY_TYPE*)attr->pValue = CKK_RSA;
				break;
			case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
				*(CK_KEY_TYPE*)attr->pValue = CKK_GOSTR3410;
				break;
			case SC_PKCS15_TYPE_PRKEY_EC:
				*(CK_KEY_TYPE*)attr->pValue = CKK_EC;
				break;
			default:
				return CKR_GENERAL_ERROR; /* Internal error*/
		}
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
	/* XXX: this should be removed sometimes as a private key has no
	 * CKA_MODULUS_BITS attribute, but unfortunately other parts depend
	 * on this -- Nils */
	case CKA_MODULUS_BITS:
		check_attribute_buffer(attr, sizeof(CK_ULONG));
		switch (prkey->prv_p15obj->type) {
			case SC_PKCS15_TYPE_PRKEY_EC:
				if (key)
					*(CK_ULONG *) attr->pValue = key->u.ec.field_length; 
				else 
					*(CK_ULONG *) attr->pValue = 384; /* TODO -DEE needs work */
				return CKR_OK;
			default:
				*(CK_ULONG *) attr->pValue = prkey->prv_info->modulus_length;
				return CKR_OK;
		}
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
	case CKA_GOSTR3410_PARAMS:
		if (prkey->prv_info && prkey->prv_info->params_len)
			return get_gostr3410_params(prkey->prv_info->params,
					prkey->prv_info->params_len, attr);
		else
			return CKR_ATTRIBUTE_TYPE_INVALID;
	case CKA_EC_PARAMS:
		return get_ec_pubkey_params(key, attr); /* get from pubkey for now */
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	return CKR_OK;
}

static CK_RV pkcs15_prkey_sign(struct sc_pkcs11_session *ses, void *obj,
			CK_MECHANISM_PTR pMechanism, CK_BYTE_PTR pData,
			CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
			CK_ULONG_PTR pulDataLen)
{
	struct pkcs15_prkey_object *prkey = (struct pkcs15_prkey_object *) obj;
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) ses->slot->card->fw_data;
	int rv, flags = 0;

	sc_debug(context, SC_LOG_DEBUG_NORMAL, "Initiating signing operation, mechanism 0x%x.\n",
				pMechanism->mechanism);

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
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE;
		break;
	case CKM_MD5_RSA_PKCS:
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_MD5;
		break;
	case CKM_SHA1_RSA_PKCS:
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA1;
		break;
	case CKM_SHA256_RSA_PKCS:
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA256;
		break;
	case CKM_SHA384_RSA_PKCS:
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA384;
		break;
	case CKM_SHA512_RSA_PKCS:
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_SHA512;
		break;
	case CKM_RIPEMD160_RSA_PKCS:
		flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_RIPEMD160;
		break;
	case CKM_RSA_X_509:
		flags = SC_ALGORITHM_RSA_RAW;
		break;
	case CKM_GOSTR3410:
		flags = SC_ALGORITHM_GOSTR3410_HASH_NONE;
		break;
	case CKM_GOSTR3410_WITH_GOSTR3411:
		flags = SC_ALGORITHM_GOSTR3410_HASH_GOSTR3411;
		break;
	case CKM_ECDSA:
		flags = SC_ALGORITHM_ECDSA_HASH_NONE;
		break;
	case CKM_ECDSA_SHA1:
		flags = SC_ALGORITHM_ECDSA_HASH_SHA1;
		break;
#if 0
	case CKM_ECDSA_SHA224:
		flags = SC_ALGORITHM_ECDSA_HASH_SHA224;
		break;
	case CKM_ECDSA_SHA256:
		flags = SC_ALGORITHM_ECDSA_HASH_SHA256;
		break;
	case CKM_ECDSA_SHA384:
		flags = SC_ALGORITHM_ECDSA_HASH_SHA384;
		break;
	case CKM_ECDSA_SHA512:
		flags = SC_ALGORITHM_ECDSA_HASH_SHA512;
		break;
#endif
	default:
		sc_debug(context, SC_LOG_DEBUG_NORMAL, "DEE - need EC for %d",pMechanism->mechanism);
		return CKR_MECHANISM_INVALID;
	}

	rv = sc_lock(ses->slot->card->card);
	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_Sign");

	if (!sc_pkcs11_conf.lock_login) {
		rv = reselect_app_df(fw_data->p15_card);
		if (rv < 0) {
			sc_unlock(ses->slot->card->card);
			return sc_to_cryptoki_error(rv, "C_Sign");
		}
	}

	sc_debug(context, SC_LOG_DEBUG_NORMAL, "Selected flags %X. Now computing signature for %d bytes. %d bytes reserved.\n", flags, ulDataLen, *pulDataLen);
	rv = sc_pkcs15_compute_signature(fw_data->p15_card,
					 prkey->prv_p15obj,
					 flags,
					 pData,
					 ulDataLen,
					 pSignature,
					 *pulDataLen);

	sc_unlock(ses->slot->card->card);

	sc_debug(context, SC_LOG_DEBUG_NORMAL, "Sign complete. Result %d.\n", rv);

	if (rv > 0) {
		*pulDataLen = rv;
		return CKR_OK;
	}

	return sc_to_cryptoki_error(rv, "C_Sign");
}

static CK_RV
pkcs15_prkey_decrypt(struct sc_pkcs11_session *ses, void *obj,
		CK_MECHANISM_PTR pMechanism,
		CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
		CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) ses->slot->card->fw_data;
	struct pkcs15_prkey_object *prkey;
	u8	decrypted[256]; /* FIXME: Will not work for keys above 2048 bits */
	int	buff_too_small, rv, flags = 0;

	sc_debug(context, SC_LOG_DEBUG_NORMAL, "Initiating decryption.\n");

	/* See which of the alternative keys supports decrypt */
	prkey = (struct pkcs15_prkey_object *) obj;
	while (prkey
	 && !(prkey->prv_info->usage
	     & (SC_PKCS15_PRKEY_USAGE_DECRYPT|SC_PKCS15_PRKEY_USAGE_UNWRAP)))
		prkey = prkey->prv_next;

	if (prkey == NULL)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;

	/* Select the proper padding mechanism */
	switch (pMechanism->mechanism) {
	case CKM_RSA_PKCS:
		flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
		break;
	case CKM_RSA_X_509:
		flags |= SC_ALGORITHM_RSA_RAW;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	rv = sc_lock(ses->slot->card->card);
	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_Decrypt");

	if (!sc_pkcs11_conf.lock_login) {
		rv = reselect_app_df(fw_data->p15_card);
		if (rv < 0) {
			sc_unlock(ses->slot->card->card);
			return sc_to_cryptoki_error(rv, "C_Decrypt");
		}
	}

	rv = sc_pkcs15_decipher(fw_data->p15_card, prkey->prv_p15obj,
				 flags, pEncryptedData, ulEncryptedDataLen,
				 decrypted, sizeof(decrypted));

	sc_unlock(ses->slot->card->card);

	sc_debug(context, SC_LOG_DEBUG_NORMAL, "Decryption complete. Result %d.\n", rv);

	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_Decrypt");

	buff_too_small = (*pulDataLen < (CK_ULONG)rv);
	*pulDataLen = rv;
	if (pData == NULL_PTR)
		return CKR_OK;
	if (buff_too_small)
		return CKR_BUFFER_TOO_SMALL;
	memcpy(pData, decrypted, *pulDataLen);

	return CKR_OK;
}

struct sc_pkcs11_object_ops pkcs15_prkey_ops = {
	pkcs15_prkey_release,
	pkcs15_prkey_set_attribute,
	pkcs15_prkey_get_attribute,
	sc_pkcs11_any_cmp_attribute,
	pkcs15_any_destroy,
	NULL,
	pkcs15_prkey_sign,
	NULL, /* unwrap */
	pkcs15_prkey_decrypt
};

/*
 * PKCS#15 RSA Public Key Object
 */
static void pkcs15_pubkey_release(void *object)
{
	struct pkcs15_pubkey_object *pubkey = (struct pkcs15_pubkey_object*) object;
	struct sc_pkcs15_pubkey *key_data = pubkey->pub_data;

	if (__pkcs15_release_object((struct pkcs15_any_object *) object) == 0) {
		if (key_data) 
			sc_pkcs15_free_pubkey(key_data);
	}
}

static CK_RV pkcs15_pubkey_set_attribute(struct sc_pkcs11_session *session,
                               void *object,
                               CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_pubkey_object *pubkey = (struct pkcs15_pubkey_object*) object;
	return pkcs15_set_attrib(session, pubkey->base.p15_object, attr);
}

static CK_RV pkcs15_pubkey_get_attribute(struct sc_pkcs11_session *session,
				void *object,
				CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_pubkey_object *pubkey = (struct pkcs15_pubkey_object*) object;
	struct pkcs15_cert_object *cert = pubkey->pub_genfrom;
	struct pkcs15_fw_data *fw_data = (struct pkcs15_fw_data *) session->slot->card->fw_data;
	size_t len;

	/* We may need to get these from cert */
	switch (attr->type) {
		case CKA_MODULUS:
		case CKA_MODULUS_BITS:
		case CKA_VALUE:
		case CKA_PUBLIC_EXPONENT:
		case CKA_EC_PARAMS:
		case CKA_EC_POINT:
			if (pubkey->pub_data == NULL) 
				/* FIXME: check the return value? */
				check_cert_data_read(fw_data, cert);
			break;
	}

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
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		if (pubkey->pub_p15obj) {
			*(CK_BBOOL*)attr->pValue =
				(pubkey->pub_p15obj->flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0;
		} else if (cert && cert->cert_p15obj) {
			*(CK_BBOOL*)attr->pValue =
				(cert->pub_p15obj->flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0;
		} else  {
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
		break;
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
		/* TODO: -DEE why would we not have a pubkey->pub_data? */
		/* even if we do not, we should not assume RSA */
		if (pubkey->pub_data && pubkey->pub_data->algorithm == SC_ALGORITHM_GOSTR3410)
			*(CK_KEY_TYPE*)attr->pValue = CKK_GOSTR3410;
		else if (pubkey->pub_data && pubkey->pub_data->algorithm == SC_ALGORITHM_EC)
			*(CK_KEY_TYPE*)attr->pValue = CKK_EC;
		else
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
			/* TODO: -DEE  Not all pubkeys have CKA_VALUE attribute. RSA and EC
		 	 * for example don't. So why is this here? 
			 * Why checking for cert in this pkcs15_pubkey_get_attribute?
		 	 */
			check_attribute_buffer(attr, pubkey->pub_data->data.len);
			memcpy(attr->pValue, pubkey->pub_data->data.value,
					      pubkey->pub_data->data.len);
		} else if (cert && cert->cert_data) {
			check_attribute_buffer(attr, cert->cert_data->data_len);
			memcpy(attr->pValue, cert->cert_data->data, cert->cert_data->data_len);
		}
		break;
	case CKA_GOSTR3410_PARAMS:
		if (pubkey->pub_info && pubkey->pub_info->params_len)
			return get_gostr3410_params(pubkey->pub_info->params,
					pubkey->pub_info->params_len, attr);
		else
			return CKR_ATTRIBUTE_TYPE_INVALID;
	case CKA_EC_PARAMS:
		return get_ec_pubkey_params(pubkey->pub_data, attr);
	case CKA_EC_POINT:
		return get_ec_pubkey_point(pubkey->pub_data, attr);
					
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
	pkcs15_any_destroy,
	NULL,
	NULL,
	NULL,
	NULL
};


/* PKCS#15 Data Object*/

static void pkcs15_dobj_release(void *object)
{
	__pkcs15_release_object((struct pkcs15_any_object *) object);
}

static CK_RV pkcs15_dobj_set_attribute(struct sc_pkcs11_session *session,
		void *object, CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_data_object *dobj = (struct pkcs15_data_object*) object;
	
	return pkcs15_set_attrib(session, dobj->base.p15_object, attr);
}


static int pkcs15_dobj_get_value(struct sc_pkcs11_session *session,
		struct pkcs15_data_object *dobj,
		struct sc_pkcs15_data **out_data)
{
	int rv;
	struct pkcs15_fw_data *fw_data =
		(struct pkcs15_fw_data *) session->slot->card->fw_data;
	sc_card_t *card = session->slot->card->card;

	if (!out_data)
		return SC_ERROR_INVALID_ARGUMENTS;
	
	rv = sc_lock(card);
	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_GetAttributeValue");
		
	rv = sc_pkcs15_read_data_object(fw_data->p15_card, dobj->info, out_data);

	sc_unlock(card);
	if (rv < 0)
		return sc_to_cryptoki_error(rv, "C_GetAttributeValue");

	return rv;
}

static CK_RV data_value_to_attr(CK_ATTRIBUTE_PTR attr, struct sc_pkcs15_data *data)
{
	if (!attr || !data)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	sc_debug(context, SC_LOG_DEBUG_NORMAL, "data %p\n", data);
	sc_debug(context, SC_LOG_DEBUG_NORMAL, "data_len %i\n", data->data_len);

	check_attribute_buffer(attr, data->data_len);
	memcpy(attr->pValue, data->data, data->data_len);
	return CKR_OK;
}

static CK_RV pkcs15_dobj_get_attribute(struct sc_pkcs11_session *session,
				void *object,
				CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_data_object *dobj = (struct pkcs15_data_object*) object;
	size_t len;
	
	switch (attr->type) {
	case CKA_CLASS:
		check_attribute_buffer(attr, sizeof(CK_OBJECT_CLASS));
		*(CK_OBJECT_CLASS*)attr->pValue = CKO_DATA;
		break;
	case CKA_TOKEN:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = TRUE;
		break;
	case CKA_PRIVATE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue =
			(dobj->base.p15_object->flags & SC_PKCS15_CO_FLAG_PRIVATE) != 0;
		break;
	case CKA_MODIFIABLE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue =
			(dobj->base.p15_object->flags & 0x02) != 0;
		break;
	case CKA_LABEL:
		len = strlen(dobj->base.p15_object->label);
		check_attribute_buffer(attr, len);
		memcpy(attr->pValue, dobj->base.p15_object->label, len);
		break;
	case CKA_APPLICATION:
		len = strlen(dobj->info->app_label);
		check_attribute_buffer(attr, len);
		memcpy(attr->pValue, dobj->info->app_label, len);
		break;
#if 0
	case CKA_ID:
		check_attribute_buffer(attr, dobj->info->id.len);
		memcpy(attr->pValue, dobj->info->id.value, dobj->info->id.len);
		break;
#endif
	case CKA_OBJECT_ID:
		{
			len = sizeof(dobj->info->app_oid);
			
			check_attribute_buffer(attr, len);
			memcpy(attr->pValue, dobj->info->app_oid.value, len);
		}
		break;
	case CKA_VALUE:
		{
			CK_RV rv;
			struct sc_pkcs15_data *data = NULL;
			
			rv = pkcs15_dobj_get_value(session, dobj, &data);
			if (rv == CKR_OK)
				rv = data_value_to_attr(attr, data);
			if (data) {
				free(data->data);
				free(data);
			}
			if (rv != CKR_OK)
				return rv;
		}
		break;
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
	
	return CKR_OK;
}

struct sc_pkcs11_object_ops pkcs15_dobj_ops = {
	pkcs15_dobj_release,
	pkcs15_dobj_set_attribute,
	pkcs15_dobj_get_attribute,
	sc_pkcs11_any_cmp_attribute,
	pkcs15_any_destroy,
	NULL,
	NULL,
	NULL,
	NULL,
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

static CK_RV
get_ec_pubkey_params(struct sc_pkcs15_pubkey *key, CK_ATTRIBUTE_PTR attr)
{
		struct sc_ec_params * ecp;
	    if (key == NULL)
			return CKR_ATTRIBUTE_TYPE_INVALID;
		if (key->alg_id == NULL) 
			return CKR_ATTRIBUTE_TYPE_INVALID;
			ecp = (struct sc_ec_params *) key->alg_id->params;

		switch (key->algorithm) {
		case SC_ALGORITHM_EC:
			check_attribute_buffer(attr, ecp->der_len);
			memcpy(attr->pValue, ecp->der, ecp->der_len);
			return CKR_OK;
		}
		return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV
get_ec_pubkey_point(struct sc_pkcs15_pubkey *key, CK_ATTRIBUTE_PTR attr)
{
	    if (key == NULL)
			return CKR_ATTRIBUTE_TYPE_INVALID;

		switch (key->algorithm) {
		case SC_ALGORITHM_EC:
			check_attribute_buffer(attr, key->u.ec.ecpointQ.len);
			memcpy(attr->pValue, key->u.ec.ecpointQ.value, key->u.ec.ecpointQ.len);
			return CKR_OK;
		}
		return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV
get_gostr3410_params(const u8 *params, size_t params_len, CK_ATTRIBUTE_PTR attr)
{
	size_t i;

	if (!params || params_len == sizeof(int))
		return CKR_ATTRIBUTE_TYPE_INVALID;

	for (i = 0; i < sizeof(gostr3410_param_oid)/
			sizeof(gostr3410_param_oid[0]); ++i) {
		if (gostr3410_param_oid[i].param == ((int*)params)[0]) {
			check_attribute_buffer(attr, sizeof(gostr3410_param_oid[i].oid));
			memcpy(attr->pValue, gostr3410_param_oid[i].oid,
					sizeof(gostr3410_param_oid[i].oid));
			return CKR_OK;
		}
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
	size_t		lenb = 1;

	len2 = len;
	/* calculate the number of bytes needed for the length */
	if (len > 127) {
		unsigned int i;
		for (i = 0; (len & (0xff << i)) != 0 && (0xff << i) != 0; i++)
			lenb++;
	}
	check_attribute_buffer(attr, 1 + lenb + len);

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

static int register_gost_mechanisms(struct sc_pkcs11_card *p11card, int flags)
{
	CK_MECHANISM_INFO mech_info;
	sc_pkcs11_mechanism_type_t *mt;
	int rc;

	mech_info.flags = CKF_HW | CKF_SIGN | CKF_DECRYPT;
#ifdef ENABLE_OPENSSL
	/* That practise definitely conflicts with CKF_HW -- andre 2010-11-28 */
	mech_info.flags |= CKF_VERIFY;
#endif
	mech_info.ulMinKeySize = SC_PKCS15_GOSTR3410_KEYSIZE;
	mech_info.ulMaxKeySize = SC_PKCS15_GOSTR3410_KEYSIZE;

	if (flags & SC_ALGORITHM_GOSTR3410_HASH_NONE) {
		mt = sc_pkcs11_new_fw_mechanism(CKM_GOSTR3410,
				&mech_info, CKK_GOSTR3410, NULL);
		if (!mt)
			return CKR_HOST_MEMORY;
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;
	}
	if (flags & SC_ALGORITHM_GOSTR3410_HASH_GOSTR3411) {
		mt = sc_pkcs11_new_fw_mechanism(CKM_GOSTR3410_WITH_GOSTR3411,
				&mech_info, CKK_GOSTR3410, NULL);
		if (!mt)
			return CKR_HOST_MEMORY;
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;
	}
	return CKR_OK;
}

static int register_ec_mechanisms(struct sc_pkcs11_card *p11card, int flags, 
			unsigned long ext_flags, int min_key_size, int max_key_size)
{
	CK_MECHANISM_INFO mech_info;
	sc_pkcs11_mechanism_type_t *mt;
	int rc;
	
	mech_info.flags = CKF_HW | CKF_SIGN; /* check for more */
	if (ext_flags & SC_ALGORITHM_EXT_EC_F_P)
		mech_info.flags |= CKF_EC_F_P;
	if (ext_flags & SC_ALGORITHM_EXT_EC_F_2M)
		mech_info.flags |= CKF_EC_F_2M;
	if (ext_flags & SC_ALGORITHM_EXT_EC_ECPARAMETERS)
		mech_info.flags |= CKF_EC_ECPARAMETERS;
	if (ext_flags & SC_ALGORITHM_EXT_EC_NAMEDCURVE)
		mech_info.flags |= CKF_EC_NAMEDCURVE;
	if (ext_flags & SC_ALGORITHM_EXT_EC_UNCOMPRESES)
		mech_info.flags |= CKF_EC_UNCOMPRESES;
	if (ext_flags & SC_ALGORITHM_EXT_EC_COMPRESS)
		mech_info.flags |= CKF_EC_COMPRESS;
	mech_info.ulMinKeySize = min_key_size;
	mech_info.ulMaxKeySize = max_key_size;
	mt = sc_pkcs11_new_fw_mechanism(CKM_ECDSA,
		&mech_info, CKK_EC, NULL);
	if (!mt)
		return CKR_HOST_MEMORY;
	rc = sc_pkcs11_register_mechanism(p11card, mt);
	if (rc != CKR_OK)
		return rc;

#if ENABLE_OPENSSL
	mt = sc_pkcs11_new_fw_mechanism(CKM_ECDSA_SHA1,
		&mech_info, CKK_EC, NULL);
	if (!mt)
		return CKR_HOST_MEMORY;
	rc = sc_pkcs11_register_mechanism(p11card, mt);
	if (rc != CKR_OK)
		return rc;
#endif

#if 0
/* TODO: -DEE Add CKM_ECDH1_COFACTOR_DERIVE  as PIV can do this */
/* TODO: -DEE But this requires C_DeriveKey to be implemented */

	mech_info.flags &= ~CKF_SIGN;
	mech_info.flags |= CKF_DRIVE;

	sc_pkcs11_new_fw_mechanism(CKM_ECDH1_COFACTOR_DERIVE,
		CKM_ECDH1_COFACTOR_DERIVE, NULL);
#endif

	return CKR_OK;
}
	
/*
 * Mechanism handling
 * FIXME: We should consult the card's algorithm list to
 * find out what operations it supports
 */
static int register_mechanisms(struct sc_pkcs11_card *p11card)
{
	sc_card_t *card = p11card->card;
	sc_algorithm_info_t *alg_info;
	CK_MECHANISM_INFO mech_info;
	int ec_min_key_size, ec_max_key_size;
	unsigned long ec_ext_flags;
	sc_pkcs11_mechanism_type_t *mt;
	unsigned int num;
	int rc, flags = 0;

	/* Register generic mechanisms */
	sc_pkcs11_register_generic_mechanisms(p11card);

	mech_info.flags = CKF_HW | CKF_SIGN | CKF_DECRYPT;
#ifdef ENABLE_OPENSSL
	/* That practise definitely conflicts with CKF_HW -- andre 2010-11-28 */
	mech_info.flags |= CKF_VERIFY;
#endif
	mech_info.ulMinKeySize = ~0;
	mech_info.ulMaxKeySize = 0;
	ec_min_key_size = ~0;
	ec_max_key_size = 0;
	ec_ext_flags = 0;

	/* For now, we just OR all the algorithm specific
	 * flags, based on the assumption that cards don't
	 * support different modes for different key sizes
	 * But we need to do this by type of key as
	 * each has different min/max and different flags.  
	 *
	 * TODO: -DEE This code assumed RSA, but the GOST 
	 * and EC code was forced in. There should be a 
	 * routine for each key type.
	 */
	num = card->algorithm_count;
	alg_info = card->algorithms;
	while (num--) {
		switch (alg_info->algorithm) {
			case SC_ALGORITHM_RSA:
				if (alg_info->key_length < mech_info.ulMinKeySize)
					mech_info.ulMinKeySize = alg_info->key_length;
				if (alg_info->key_length > mech_info.ulMaxKeySize)
					mech_info.ulMaxKeySize = alg_info->key_length;
				flags |= alg_info->flags;
				break;
			case SC_ALGORITHM_EC:
				if (alg_info->key_length < ec_min_key_size)
					ec_min_key_size = alg_info->key_length;
				if (alg_info->key_length > ec_max_key_size)
					ec_max_key_size = alg_info->key_length;
				flags |= alg_info->flags;
				ec_ext_flags |= alg_info->u._ec.ext_flags;
				break;
			case SC_ALGORITHM_GOSTR3410:
				flags |= alg_info->flags;
				break;
		}
		alg_info++;
	}

	if (flags & SC_ALGORITHM_ECDSA_RAW) {
		rc = register_ec_mechanisms(p11card, flags, ec_ext_flags, ec_min_key_size, ec_max_key_size);
	}

	if (flags & (SC_ALGORITHM_GOSTR3410_RAW
				| SC_ALGORITHM_GOSTR3410_HASH_NONE
				| SC_ALGORITHM_GOSTR3410_HASH_GOSTR3411)) {
		if (flags & SC_ALGORITHM_GOSTR3410_RAW)
			flags |= SC_ALGORITHM_GOSTR3410_HASH_NONE;
		rc = register_gost_mechanisms(p11card, flags);
		if (rc != CKR_OK)
			return rc;
	}

	/* Check if we support raw RSA */
	if (flags & SC_ALGORITHM_RSA_RAW) {
		mt = sc_pkcs11_new_fw_mechanism(CKM_RSA_X_509, &mech_info, CKK_RSA, NULL);
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;

		/* If the card supports RAW, it should by all means
		 * have registered everything else, too. If it didn't
		 * we help it a little
		 */
		flags |= SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASHES;
	}

	/* Check for PKCS1 */
	if (flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
		mt = sc_pkcs11_new_fw_mechanism(CKM_RSA_PKCS, &mech_info, CKK_RSA, NULL);
		rc = sc_pkcs11_register_mechanism(p11card, mt);
		if (rc != CKR_OK)
			return rc;

		/* if the driver doesn't say what hashes it supports,
		 * claim we will do all of them */
		if (!(flags & SC_ALGORITHM_RSA_HASHES))
			flags |= SC_ALGORITHM_RSA_HASHES;

		if (flags & SC_ALGORITHM_RSA_HASH_SHA1) {
			rc = sc_pkcs11_register_sign_and_hash_mechanism(p11card, CKM_SHA1_RSA_PKCS, CKM_SHA_1, mt);
			if (rc != CKR_OK)
				return rc;
		}
		if (flags & SC_ALGORITHM_RSA_HASH_SHA256) {
			rc = sc_pkcs11_register_sign_and_hash_mechanism(p11card, CKM_SHA256_RSA_PKCS, CKM_SHA256, mt);
			if (rc != CKR_OK)
				return rc;
		}
		if (flags & SC_ALGORITHM_RSA_HASH_MD5) {
			rc = sc_pkcs11_register_sign_and_hash_mechanism(p11card, CKM_MD5_RSA_PKCS, CKM_MD5, mt);
			if (rc != CKR_OK)
				return rc;
		}
		if (flags & SC_ALGORITHM_RSA_HASH_RIPEMD160) {
			rc = sc_pkcs11_register_sign_and_hash_mechanism(p11card, CKM_RIPEMD160_RSA_PKCS, CKM_RIPEMD160, mt);
			if (rc != CKR_OK)
				return rc;
		}

		if (flags & SC_ALGORITHM_ONBOARD_KEY_GEN) {
			mech_info.flags = CKF_GENERATE_KEY_PAIR;
			mt = sc_pkcs11_new_fw_mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, &mech_info, CKK_RSA, NULL);
			if (!mt)
				return CKR_HOST_MEMORY;
			rc = sc_pkcs11_register_mechanism(p11card, mt);
			if (rc != CKR_OK)
				return rc;
		}	
	}

	return CKR_OK;
}

static int lock_card(struct pkcs15_fw_data *fw_data)
{
	int	rc;

	if ((rc = sc_lock(fw_data->p15_card->card)) < 0)
		sc_debug(context, SC_LOG_DEBUG_NORMAL, "Failed to lock card (%d)\n", rc);
	else
		fw_data->locked++;

	return rc;
}

static int unlock_card(struct pkcs15_fw_data *fw_data)
{
	while (fw_data->locked) {
		sc_unlock(fw_data->p15_card->card);
		fw_data->locked--;
	}
	return 0;
}


static int reselect_app_df(sc_pkcs15_card_t *p15card)
{
	int r = SC_SUCCESS;

	if (p15card->file_app != NULL) {
		/* if the application df (of the pkcs15 application) is
		 * specified select it */
		sc_path_t *tpath = &p15card->file_app->path;
		sc_debug(p15card->card->ctx, SC_LOG_DEBUG_NORMAL, "reselect application df\n");
		r = sc_select_file(p15card->card, tpath, NULL);
	}
	return r;
}
