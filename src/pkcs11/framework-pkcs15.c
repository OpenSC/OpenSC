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
#include <malloc.h>
#include <string.h>
#include "sc-pkcs11.h"

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

extern struct sc_pkcs11_object_ops pkcs15_cert_ops;
extern struct sc_pkcs11_object_ops pkcs15_prkey_ops;
extern struct sc_pkcs11_object_ops pkcs15_cert_key_ops;
extern struct sc_pkcs11_object_ops pkcs15_pubkey_ops;

struct pkcs15_cert_object {
	struct sc_pkcs11_object object;

        struct sc_pkcs15_object *certificate_object;
	struct sc_pkcs15_cert_info *certificate_info;
        struct sc_pkcs15_cert *certificate;
};

struct pkcs15_prkey_object {
	struct sc_pkcs11_object object;

        struct sc_pkcs15_object *prkey_object;
	struct sc_pkcs15_prkey_info *prkey_info;
        struct pkcs15_cert_object *cert_object;
	struct pkcs15_pubkey_object *pubkey_object;
};

struct pkcs15_cert_key_object {
	struct sc_pkcs11_object object;

        struct sc_pkcs15_object *certificate_object;
	struct sc_pkcs15_cert_info *certificate_info;
	struct sc_pkcs15_pubkey_rsa *rsakey;
};

struct pkcs15_pubkey_object {
	struct sc_pkcs11_object object;

	struct sc_pkcs15_object *pubkey_object;
	struct sc_pkcs15_pubkey_info *pubkey_info;
	struct sc_pkcs15_pubkey_rsa *rsakey;
};

static int	get_public_exponent(struct sc_pkcs15_pubkey_rsa *,
					CK_ATTRIBUTE_PTR);
static int	get_modulus(struct sc_pkcs15_pubkey_rsa *,
					CK_ATTRIBUTE_PTR);
static int	get_modulus_bits(struct sc_pkcs15_pubkey_rsa *,
					CK_ATTRIBUTE_PTR);
static int	asn1_sequence_wrapper(const u8 *, size_t, CK_ATTRIBUTE_PTR);

/* PKCS#15 Framework */

static CK_RV pkcs15_bind(struct sc_pkcs11_card *p11card)
{
	int rc = sc_pkcs15_bind(p11card->card,
				(struct sc_pkcs15_card**) &p11card->fw_data);
	debug(context, "Binding to PKCS#15, rc=%d\n", rc);
        return sc_to_cryptoki_error(rc, p11card->reader);
}

static CK_RV pkcs15_unbind(struct sc_pkcs11_card *p11card)
{
        struct sc_pkcs15_card *card = (struct sc_pkcs15_card*) p11card->fw_data;
	int rc = sc_pkcs15_unbind(card);
        return sc_to_cryptoki_error(rc, p11card->reader);
}

static void pkcs15_init_token_info(struct sc_pkcs15_card *card, CK_TOKEN_INFO_PTR pToken)
{
	strcpy_bp(pToken->manufacturerID, card->manufacturer_id, 32);
	strcpy_bp(pToken->model, "PKCS #15 SCard", 16);
	strcpy_bp(pToken->serialNumber, card->serial_number, 16);
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

static struct pkcs15_cert_object *pkcs15_add_cert_object(struct sc_pkcs11_slot *slot,
                                   struct sc_pkcs15_card *card,
				   struct sc_pkcs15_object *cert)
{
	struct pkcs15_cert_object *object;
        struct pkcs15_cert_key_object *obj2;

        /* Certificate object */
        object = (struct pkcs15_cert_object*) calloc(1, sizeof(struct pkcs15_cert_object));
	object->object.ops = &pkcs15_cert_ops;
	object->certificate_object = cert;
        object->certificate_info = (struct sc_pkcs15_cert_info*) cert->data;
	sc_pkcs15_read_certificate(card, object->certificate_info, &object->certificate);
	pool_insert(&slot->object_pool, object, NULL);

        /* Corresponding public key */
        obj2 = (struct pkcs15_cert_key_object*) calloc(1, sizeof(struct pkcs15_cert_key_object));
	obj2->object.ops = &pkcs15_cert_key_ops;
	obj2->rsakey = &object->certificate->key;
	obj2->certificate_object = cert;
        obj2->certificate_info = (struct sc_pkcs15_cert_info*) cert->data;
	pool_insert(&slot->object_pool, obj2, NULL);

	/* Mark as seen */
	cert->flags |= SC_PKCS15_CO_FLAG_OBJECT_SEEN;

        return object;
}

static struct pkcs15_pubkey_object *pkcs15_add_pubkey_object(struct sc_pkcs11_slot *slot,
				struct sc_pkcs15_card *card,
				struct sc_pkcs15_object *pubkey)
{
	struct pkcs15_pubkey_object *object;

        /* Certificate object */
        object = (struct pkcs15_pubkey_object*) calloc(1, sizeof(struct pkcs15_pubkey_object));
	object->object.ops = &pkcs15_pubkey_ops;
	object->pubkey_object = pubkey;
        object->pubkey_info = (struct sc_pkcs15_pubkey_info*) pubkey->data;
	sc_pkcs15_read_pubkey(card, object->pubkey_info, &object->rsakey);
	pool_insert(&slot->object_pool, object, NULL);

	/* Mark as seen */
	pubkey->flags |= SC_PKCS15_CO_FLAG_OBJECT_SEEN;

        return object;
}

static struct pkcs15_prkey_object *pkcs15_add_prkey_object(struct sc_pkcs11_slot *slot,
							   struct sc_pkcs15_card *card,
							   struct sc_pkcs15_object *prkey,
							   struct sc_pkcs15_object **certs,
                                                           int cert_count,
							   struct sc_pkcs15_object **pubkeys,
							   int pubkey_count
							  )
{
	struct pkcs15_prkey_object *object;
        int i;

        object = (struct pkcs15_prkey_object*) calloc(1, sizeof(struct pkcs15_prkey_object));
	object->object.ops = &pkcs15_prkey_ops;
        object->prkey_object = prkey;
        object->prkey_info = (struct sc_pkcs15_prkey_info*) prkey->data;
	pool_insert(&slot->object_pool, object, NULL);

	/* Mark as seen */
        prkey->flags |= SC_PKCS15_CO_FLAG_OBJECT_SEEN;

	/* Also add the related certificate if found */
	for (i=0; i < cert_count; i++) {
		if (sc_pkcs15_compare_id(&object->prkey_info->id,
					 &((struct sc_pkcs15_cert_info*)certs[i]->data)->id)) {
			debug(context, "Adding certificate %d relating to private key\n", i);
                        object->cert_object = pkcs15_add_cert_object(slot, card, certs[i]);
                        break;
		}
	}

	/* Add public key if found */
	for (i=0; i < pubkey_count; i++) {
		if (sc_pkcs15_compare_id(&object->prkey_info->id,
					 &((struct sc_pkcs15_pubkey_info*)pubkeys[i]->data)->id)) {
			debug(context, "Adding public key %d relating to private key\n", i);
                        object->pubkey_object = pkcs15_add_pubkey_object(slot, card, pubkeys[i]);
                        break;
		}
	}

        return object;
}

static CK_RV pkcs15_create_slot(struct sc_pkcs11_card *p11card,
		struct sc_pkcs15_object *auth,
		struct sc_pkcs11_slot **out)
{
        struct sc_pkcs15_card *card = (struct sc_pkcs15_card*) p11card->fw_data;
	struct sc_pkcs15_pin_info *pin_info = NULL;
	struct sc_pkcs11_slot *slot;
	char tmp[64];
	int rv;

	if (*out)
		return CKR_OK;

	rv = slot_allocate(&slot, p11card);
	if (rv != CKR_OK)
		return rv;

	pkcs15_init_token_info(card, &slot->token_info);
	slot->token_info.flags = CKF_USER_PIN_INITIALIZED
				| CKF_TOKEN_INITIALIZED
				| CKF_WRITE_PROTECTED;
	slot->fw_data = auth;

	if (auth != NULL) {
		pin_info = (struct sc_pkcs15_pin_info*) auth->data;

		snprintf(tmp, sizeof(tmp), "%s (%s)",
				card->label, auth->label);
		slot->token_info.flags |= CKF_LOGIN_REQUIRED;
	} else
		sprintf(tmp, "public");
	strcpy_bp(slot->token_info.label, tmp, 32);

	if (pin_info && pin_info->magic == SC_PKCS15_PIN_MAGIC) {
		slot->token_info.ulMaxPinLen = pin_info->stored_length;
		slot->token_info.ulMinPinLen = pin_info->min_length;
	} else {
		/* choose reasonable defaults */
		slot->token_info.ulMaxPinLen = 8;
		slot->token_info.ulMinPinLen = 4;
	}

	debug(context, "Initialized token '%s'\n", tmp);
	*out = slot;
	return CKR_OK;
}

static CK_RV pkcs15_create_tokens(struct sc_pkcs11_card *p11card)
{
        struct sc_pkcs15_card *card = (struct sc_pkcs15_card*) p11card->fw_data;
	struct sc_pkcs11_slot *slot;

	struct sc_pkcs15_object
		*auths[SC_PKCS15_MAX_PINS],
		*certs[SC_PKCS15_MAX_CERTS],
		*prkeys[SC_PKCS15_MAX_PRKEYS],
		*pubkeys[SC_PKCS15_MAX_PUBKEYS];

	int i, j, rv, reader = p11card->reader;
        int auth_count, cert_count, prkey_count, pubkey_count;

        rv = auth_count = sc_pkcs15_get_objects(card, SC_PKCS15_TYPE_AUTH_PIN, auths, SC_PKCS15_MAX_PINS);
	if (rv < 0)
                return sc_to_cryptoki_error(rv, reader);
	debug(context, "Found %d authentication objects\n", auth_count);

        rv = cert_count = sc_pkcs15_get_objects(card, SC_PKCS15_TYPE_CERT_X509, certs, SC_PKCS15_MAX_CERTS);
	if (rv < 0)
                return sc_to_cryptoki_error(rv, reader);
	debug(context, "Found %d certificates\n", cert_count);

        rv = prkey_count = sc_pkcs15_get_objects(card, SC_PKCS15_TYPE_PRKEY_RSA, prkeys, SC_PKCS15_MAX_PRKEYS);
 	if (rv < 0)
                return sc_to_cryptoki_error(rv, reader);
	debug(context, "Found %d private keys\n", prkey_count);

        rv = pubkey_count = sc_pkcs15_get_objects(card, SC_PKCS15_TYPE_PUBKEY_RSA, pubkeys, SC_PKCS15_MAX_PUBKEYS);
 	if (rv < 0)
                return sc_to_cryptoki_error(rv, reader);
	debug(context, "Found %d public keys\n", pubkey_count);

	for (i = 0; i < auth_count; i++) {
		struct sc_pkcs15_pin_info *pin_info = NULL;

		/* Add all the private keys related to this pin */
		pin_info = (struct sc_pkcs15_pin_info*) auths[i]->data;
		slot = NULL;
		for (j=0; j < prkey_count; j++) {
			if (sc_pkcs15_compare_id(&pin_info->auth_id,
						 &prkeys[j]->auth_id)) {
				if (!slot) {
					rv = pkcs15_create_slot(p11card,
						auths[i], &slot);
					if (rv != CKR_OK)
						return rv;
				}
                                debug(context, "Adding private key %d to PIN %d\n", j, i);
				pkcs15_add_prkey_object(slot, card, prkeys[j],
					       	certs, cert_count,
						pubkeys, pubkey_count);
			}
		}
	}

	/* Add all public objects to a virtual slot without
	 * pin protection */
	slot = NULL;

	/* Add all the remaining private keys */
	for (j=0; j < prkey_count; j++) {
		if (!(prkeys[j]->flags & SC_PKCS15_CO_FLAG_OBJECT_SEEN)) {
                        debug(context, "Private key %d was not seen previously\n", j);
			if (!slot) {
				rv = pkcs15_create_slot(p11card, NULL, &slot);
				if (rv != CKR_OK)
					return rv;
			}
			pkcs15_add_prkey_object(slot, card, prkeys[j],
				       	certs, cert_count,
					pubkeys, pubkey_count);
		}
	}

	/* Add all the remaining certificates */
	for (j=0; j < cert_count; j++) {
		/* XXX netscape wants to see all certificates in a slot
		 * that doesn't require login */
		if (!(certs[j]->flags & SC_PKCS15_CO_FLAG_OBJECT_SEEN)) {
                        debug(context, "Certificate %d was not seen previously\n", j);
			if (!slot) {
				rv = pkcs15_create_slot(p11card, NULL, &slot);
				if (rv != CKR_OK)
					return rv;
			}
			pkcs15_add_cert_object(slot, card, certs[j]);
		}
	}

	/* Create read/write slots */
	while (slot_allocate(&slot, p11card) == CKR_OK) {
		pkcs15_init_token_info(card, &slot->token_info);
		slot->token_info.flags = CKF_TOKEN_INITIALIZED;
	}

	debug(context, "All tokens created\n");
	return CKR_OK;
}

static CK_RV pkcs15_release_token(struct sc_pkcs11_card *p11card, void *fw_token)
{
        /* struct sc_pkcs15_card *card = (struct sc_pkcs15_card*) fw_card; */
        return CKR_OK;
}

static CK_RV pkcs15_get_mechanism_list(struct sc_pkcs11_card *p11card,
				       void *fw_token,
				       CK_MECHANISM_TYPE_PTR pMechanismList,
				       CK_ULONG_PTR pulCount)
{
	static const CK_MECHANISM_TYPE mechanism_list[] = {
		CKM_RSA_PKCS,
                CKM_SHA1_RSA_PKCS
	};
        const int numMechanisms = sizeof(mechanism_list) / sizeof(mechanism_list[0]);

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

static CK_RV pkcs15_get_mechanism_info(struct sc_pkcs11_card *p11card,
				       void *fw_token,
				       CK_MECHANISM_TYPE type,
				       CK_MECHANISM_INFO_PTR pInfo)
{
	switch (type) {
	case CKM_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
                pInfo->flags = CKF_HW | CKF_SIGN;
		pInfo->ulMinKeySize = 512;
                pInfo->ulMaxKeySize = 2048;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}
        return CKR_OK;
}

static CK_RV pkcs15_login(struct sc_pkcs11_card *p11card,
			  void *fw_token,
			  CK_CHAR_PTR pPin,
			  CK_ULONG ulPinLen)
{
	int rc;
	struct sc_pkcs15_card *card = (struct sc_pkcs15_card*) p11card->fw_data;
        struct sc_pkcs15_object *auth_object = (struct sc_pkcs15_object*) fw_token;
	struct sc_pkcs15_pin_info *pin = (struct sc_pkcs15_pin_info*) auth_object->data;

	if (ulPinLen < pin->min_length ||
	    ulPinLen > pin->stored_length)
		return CKR_PIN_LEN_RANGE;

	rc = sc_lock(card->card);
	if (rc < 0) {
		 debug(context, "Failed to lock card (%d)\n", rc);
		 return sc_to_cryptoki_error(rc, p11card->reader);
	}

	rc = sc_pkcs15_verify_pin(card, pin, pPin, ulPinLen);
        debug(context, "PIN verification returned %d\n", rc);
	return sc_to_cryptoki_error(rc, p11card->reader);
}

static CK_RV pkcs15_logout(struct sc_pkcs11_card *p11card, void *fw_token)
{
	struct sc_pkcs15_card *card = (struct sc_pkcs15_card*) p11card->fw_data;
	int rc;

	rc = sc_unlock(card->card);
	return sc_to_cryptoki_error(rc, p11card->reader);
}

static CK_RV pkcs15_change_pin(struct sc_pkcs11_card *p11card,
			  void *fw_token,
			  CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen,
			  CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	int rc;
	struct sc_pkcs15_card *card = (struct sc_pkcs15_card*) p11card->fw_data;
        struct sc_pkcs15_object *auth_object = (struct sc_pkcs15_object*) fw_token;
	struct sc_pkcs15_pin_info *pin = (struct sc_pkcs15_pin_info*) auth_object->data;

	if (ulNewLen < pin->min_length ||
	    ulNewLen > pin->stored_length)
		return CKR_PIN_LEN_RANGE;

	rc = sc_pkcs15_change_pin(card, pin, pOldPin, ulOldLen,
				pNewPin, ulNewLen);
        debug(context, "PIN verification returned %d\n", rc);
	return sc_to_cryptoki_error(rc, p11card->reader);
}

struct sc_pkcs11_framework_ops framework_pkcs15 = {
	pkcs15_bind,
	pkcs15_unbind,
	pkcs15_create_tokens,
	pkcs15_release_token,
	pkcs15_get_mechanism_list,
	pkcs15_get_mechanism_info,
	pkcs15_login,
        pkcs15_logout,
	pkcs15_change_pin
};

/*
 * PKCS#15 Certificate Object
 */

void pkcs15_cert_release(void *obj)
{
	struct pkcs15_cert_object *cert = (struct pkcs15_cert_object *) obj;
	sc_pkcs15_free_certificate(cert->certificate);
}

CK_RV pkcs15_cert_get_attribute(struct sc_pkcs11_session *session,
				void *object,
				CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_cert_object *cert = (struct pkcs15_cert_object*) object;

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
		check_attribute_buffer(attr, strlen(cert->certificate_object->label));
                memcpy(attr->pValue, cert->certificate_object->label, strlen(cert->certificate_object->label));
                break;
	case CKA_CERTIFICATE_TYPE:
		check_attribute_buffer(attr, sizeof(CK_CERTIFICATE_TYPE));
                *(CK_CERTIFICATE_TYPE*)attr->pValue = CKC_X_509;
		break;
	case CKA_ID:
		if (cert->certificate_info->authority) {
			check_attribute_buffer(attr, 1);
			*(unsigned char*)attr->pValue = 0;
		} else {
			check_attribute_buffer(attr, cert->certificate_info->id.len);
			memcpy(attr->pValue, cert->certificate_info->id.value, cert->certificate_info->id.len);
                }
                break;
	case CKA_TRUSTED:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = cert->certificate_info->authority?TRUE:FALSE;
                break;
	case CKA_VALUE:
		check_attribute_buffer(attr, cert->certificate->data_len);
		memcpy(attr->pValue, cert->certificate->data, cert->certificate->data_len);
		break;
	case CKA_SERIAL_NUMBER:
		 check_attribute_buffer(attr, cert->certificate->serial_len);
		 memcpy(attr->pValue, cert->certificate->serial, cert->certificate->serial_len);
		 break;
	case CKA_SUBJECT:
		 return asn1_sequence_wrapper(cert->certificate->subject,
				 cert->certificate->subject_len,
				 attr);
	case CKA_ISSUER:
		 return asn1_sequence_wrapper(cert->certificate->issuer,
				 cert->certificate->issuer_len,
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
		if (cert->certificate->issuer_len == 0)
			break;
		data = attr->pValue;
		len = attr->ulValueLen;
		/* SEQUENCE is tag 0x30, SET is 0x31
		 * I know this code is icky, but hey... this is netscape
		 * we're dealing with :-) */
		if (cert->certificate->issuer[0] == 0x31
		 && data[0] == 0x30 && len >= 2) {
			/* skip the length byte(s) */
			len = (data[1] & 0x80)? (data[1] & 0x7F) : 0;
			if (attr->ulValueLen < len + 2)
				break;
			data += len + 2;
			len = attr->ulValueLen - len - 2;
		}
		if (len == cert->certificate->issuer_len
		 && !memcmp(cert->certificate->issuer, data, len))
			return 1;
		break;
	default:
                return sc_pkcs11_any_cmp_attribute(session, object, attr);
	}

        return 0;
}

struct sc_pkcs11_object_ops pkcs15_cert_ops = {
	pkcs15_cert_release,
        NULL,
	pkcs15_cert_get_attribute,
	pkcs15_cert_cmp_attribute,
	NULL,
	NULL,
        NULL
};

/*
 * PKCS#15 Private Key Object
 */

CK_RV pkcs15_prkey_get_attribute(struct sc_pkcs11_session *session,
				void *object,
				CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_prkey_object *prkey = (struct pkcs15_prkey_object*) object;
	struct sc_pkcs15_pubkey_rsa *key = NULL;

	if (prkey->cert_object && prkey->cert_object->certificate)
		key = &prkey->cert_object->certificate->key;
	else if (prkey->pubkey_object)
		key = prkey->pubkey_object->rsakey;

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
	case CKA_SIGN:
	case CKA_PRIVATE:
	case CKA_UNWRAP: /* XXX should make an attempt to find out whether
			    the card supports unwrap */
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = TRUE;
                break;
	case CKA_MODIFIABLE:
	case CKA_DERIVE:
	case CKA_DECRYPT:
	case CKA_SIGN_RECOVER:
	case CKA_EXTRACTABLE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = FALSE;
                break;
	case CKA_LABEL:
		check_attribute_buffer(attr, strlen(prkey->prkey_object->label));
                memcpy(attr->pValue, prkey->prkey_object->label, strlen(prkey->prkey_object->label));
		break;
	case CKA_KEY_TYPE:
		check_attribute_buffer(attr, sizeof(CK_KEY_TYPE));
                *(CK_KEY_TYPE*)attr->pValue = CKK_RSA;
                break;
	case CKA_ID:
		check_attribute_buffer(attr, prkey->prkey_info->id.len);
		memcpy(attr->pValue, prkey->prkey_info->id.value, prkey->prkey_info->id.len);
                break;
	case CKA_KEY_GEN_MECHANISM:
		check_attribute_buffer(attr, sizeof(CK_MECHANISM_TYPE));
                *(CK_MECHANISM_TYPE*)attr->pValue = CK_UNAVAILABLE_INFORMATION;
		break;
	case CKA_MODULUS:
		return get_modulus(key, attr);
	case CKA_MODULUS_BITS:
		return get_modulus_bits(key, attr);
	case CKA_PUBLIC_EXPONENT:
		return get_public_exponent(key, attr);
	case CKA_PRIVATE_EXPONENT:
	case CKA_PRIME_1:
	case CKA_PRIME_2:
	case CKA_EXPONENT_1:
	case CKA_EXPONENT_2:
	case CKA_COEFFICIENT:
		return CKR_ATTRIBUTE_SENSITIVE;
		/*
		 case CKA_SUBJECT:
		 case CKA_START_DATE:
		 case CKA_END_DATE:
		 */
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
	int rv, flags = 0;

	debug(context, "Initiating signing operation.\n");

	flags = SC_ALGORITHM_RSA_PAD_PKCS1;
	switch (pMechanism->mechanism) {
	case CKM_RSA_PKCS:
		/* Um. We need to guess what netscape is trying to
		 * sign here. We're lucky that all these things have
		 * different sizes. */
		switch (ulDataLen) {
		case 34:flags |= SC_ALGORITHM_RSA_HASH_MD5;  /* MD5 + header */
			pData += 18; ulDataLen -= 18;
			break;
		case 35:flags |= SC_ALGORITHM_RSA_HASH_SHA1;   /* SHA1 + hdr */
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
	case CKM_SHA1_RSA_PKCS:
		flags |= SC_ALGORITHM_RSA_HASH_SHA1;
		break;
	default:
                return CKR_MECHANISM_INVALID;
	}

        debug(context, "Selected flags %X. Now computing signature for %d bytes. %d bytes reserved.\n", flags, ulDataLen, *pulDataLen);
	rv = sc_pkcs15_compute_signature((struct sc_pkcs15_card*) ses->slot->card->fw_data,
					 prkey->prkey_object,
					 flags,
					 pData,
					 ulDataLen,
					 pSignature,
					 *pulDataLen);
        debug(context, "Sign complete. Result %d.\n", rv);

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
	struct pkcs15_prkey_object *prkey;
	struct sc_pkcs15_card *p15card;
	u8	unwrapped_key[256];
	int	rv;

	debug(context, "Initiating key unwrap.\n");

	if (pMechanism->mechanism != CKM_RSA_PKCS)
		return CKR_MECHANISM_INVALID;

	p15card = (struct sc_pkcs15_card*) ses->slot->card->fw_data;
	prkey = (struct pkcs15_prkey_object *) obj;
	rv = sc_pkcs15_decipher(p15card, prkey->prkey_object,
				 pData, ulDataLen,
				 unwrapped_key, sizeof(unwrapped_key));
	debug(context, "Key unwrap complete. Result %d.\n", rv);

	if (rv < 0)
		return sc_to_cryptoki_error(rv, ses->slot->card->reader);
	return sc_pkcs11_create_secret_key(ses,
			unwrapped_key, rv,
			pTemplate, ulAttributeCount,
			(struct sc_pkcs11_object **) result);
}

struct sc_pkcs11_object_ops pkcs15_prkey_ops = {
	NULL,
	NULL,
	pkcs15_prkey_get_attribute,
	sc_pkcs11_any_cmp_attribute,
	NULL,
	NULL,
        pkcs15_prkey_sign,
	pkcs15_prkey_unwrap
};

/*
 * PKCS#15 RSA Public Key Object (as part of certificate)
 */

CK_RV pkcs15_cert_key_get_attribute(struct sc_pkcs11_session *session,
				void *object,
				CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_cert_key_object *pubkey = (struct pkcs15_cert_key_object*) object;

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
	case CKA_ENCRYPT:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
	case CKA_WRAP:
	case CKA_DERIVE:
	case CKA_EXTRACTABLE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = FALSE;
                break;
	case CKA_LABEL:
		check_attribute_buffer(attr, strlen(pubkey->certificate_object->label));
                memcpy(attr->pValue, pubkey->certificate_object->label, strlen(pubkey->certificate_object->label));
		break;
	case CKA_KEY_TYPE:
		check_attribute_buffer(attr, sizeof(CK_KEY_TYPE));
                *(CK_KEY_TYPE*)attr->pValue = CKK_RSA;
                break;
	case CKA_ID:
		check_attribute_buffer(attr, pubkey->certificate_info->id.len);
		memcpy(attr->pValue, pubkey->certificate_info->id.value, pubkey->certificate_info->id.len);
                break;
	case CKA_KEY_GEN_MECHANISM:
		check_attribute_buffer(attr, sizeof(CK_MECHANISM_TYPE));
                *(CK_MECHANISM_TYPE*)attr->pValue = CK_UNAVAILABLE_INFORMATION;
		break;
	case CKA_MODULUS:
		return get_modulus(pubkey->rsakey, attr);
	case CKA_MODULUS_BITS:
		return get_modulus_bits(pubkey->rsakey, attr);
	case CKA_PUBLIC_EXPONENT:
		return get_public_exponent(pubkey->rsakey, attr);
	default:
                return CKR_ATTRIBUTE_TYPE_INVALID;
	}

        return CKR_OK;
}

struct sc_pkcs11_object_ops pkcs15_cert_key_ops = {
	NULL,
	NULL,
	pkcs15_cert_key_get_attribute,
	sc_pkcs11_any_cmp_attribute,
	NULL,
	NULL,
        NULL
};

/*
 * PKCS#15 RSA Public Key Object (stored on card as-is)
 */

CK_RV pkcs15_pubkey_get_attribute(struct sc_pkcs11_session *session,
				void *object,
				CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_pubkey_object *pubkey = (struct pkcs15_pubkey_object*) object;

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
	case CKA_ENCRYPT:
	case CKA_VERIFY:
	case CKA_VERIFY_RECOVER:
	case CKA_WRAP:
	case CKA_DERIVE:
	case CKA_EXTRACTABLE:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = FALSE;
                break;
	case CKA_LABEL:
		check_attribute_buffer(attr, strlen(pubkey->pubkey_object->label));
                memcpy(attr->pValue, pubkey->pubkey_object->label, strlen(pubkey->pubkey_object->label));
		break;
	case CKA_KEY_TYPE:
		check_attribute_buffer(attr, sizeof(CK_KEY_TYPE));
                *(CK_KEY_TYPE*)attr->pValue = CKK_RSA;
                break;
	case CKA_ID:
		check_attribute_buffer(attr, pubkey->pubkey_info->id.len);
		memcpy(attr->pValue, pubkey->pubkey_info->id.value, pubkey->pubkey_info->id.len);
                break;
	case CKA_KEY_GEN_MECHANISM:
		check_attribute_buffer(attr, sizeof(CK_MECHANISM_TYPE));
                *(CK_MECHANISM_TYPE*)attr->pValue = CK_UNAVAILABLE_INFORMATION;
		break;
	case CKA_MODULUS:
		return get_modulus(pubkey->rsakey, attr);
	case CKA_MODULUS_BITS:
		return get_modulus_bits(pubkey->rsakey, attr);
	case CKA_PUBLIC_EXPONENT:
		return get_public_exponent(pubkey->rsakey, attr);
	default:
                return CKR_ATTRIBUTE_TYPE_INVALID;
	}

        return CKR_OK;
}

struct sc_pkcs11_object_ops pkcs15_pubkey_ops = {
	NULL,
	NULL,
	pkcs15_pubkey_get_attribute,
	sc_pkcs11_any_cmp_attribute,
	NULL,
	NULL,
        NULL
};

/*
 * get_attribute helpers
 */
static int
get_modulus(struct sc_pkcs15_pubkey_rsa *key, CK_ATTRIBUTE_PTR attr)
{
	if (key == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	check_attribute_buffer(attr, key->modulus_len);
	memcpy(attr->pValue, key->modulus, key->modulus_len);
	return CKR_OK;
}

static int
get_modulus_bits(struct sc_pkcs15_pubkey_rsa *key, CK_ATTRIBUTE_PTR attr)
{
	CK_ULONG	bits, mask;

	if (key == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	bits = key->modulus_len * 8;
	for (mask = 0x80; mask; mask >>= 1, bits--) {
		if (key->modulus[0] & mask)
			break;
	}
	check_attribute_buffer(attr, sizeof(bits));
	*(CK_ULONG *) attr->pValue = bits;
	return CKR_OK;
}

static int
get_public_exponent(struct sc_pkcs15_pubkey_rsa *key, CK_ATTRIBUTE_PTR attr)
{
	CK_ULONG	word;
	unsigned int	j, n;
	CK_BYTE		exponent[4];

	if (key == NULL)
		return CKR_ATTRIBUTE_TYPE_INVALID;
	word = key->exponent;
	for (j = 0, n = 4; j < n; word <<= 8) {
		if ((word & 0xFF000000) || j)
			exponent[j++] = word >> 24;
		else
			n--;
	}
	check_attribute_buffer(attr, n);
	memcpy(attr->pValue, exponent, n);
	return CKR_OK;
}

static int
asn1_sequence_wrapper(const u8 *data, size_t len, CK_ATTRIBUTE_PTR attr)
{
	u8		*dest;
	unsigned int	n;

	check_attribute_buffer(attr, len + 1 + sizeof(len));

	dest = attr->pValue;
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
	memcpy(dest, data, len);
	attr->ulValueLen = (dest - (u8 *) attr->pValue) + len;
	return CKR_OK;
}
