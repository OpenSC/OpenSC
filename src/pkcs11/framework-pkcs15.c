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

#include <malloc.h>
#include <string.h>

#include "sc-pkcs11.h"
#include <sc-log.h>

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
};

struct pkcs15_pubkey_object {
	struct sc_pkcs11_object object;

        struct sc_pkcs15_object *certificate_object;
	struct sc_pkcs15_cert_info *certificate_info;
	struct sc_pkcs15_pubkey_rsa *rsakey;
};

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
        struct pkcs15_pubkey_object *obj2;

        /* Certificate object */
        object = (struct pkcs15_cert_object*) malloc(sizeof(struct pkcs15_cert_object));
	object->object.ops = &pkcs15_cert_ops;
	object->certificate_object = cert;
        object->certificate_info = (struct sc_pkcs15_cert_info*) cert->data;
	sc_pkcs15_read_certificate(card, object->certificate_info, &object->certificate);
	pool_insert(&slot->object_pool, object, NULL);

        /* Corresponding public key */
        obj2 = (struct pkcs15_pubkey_object*) malloc(sizeof(struct pkcs15_pubkey_object));
	obj2->object.ops = &pkcs15_pubkey_ops;
	obj2->rsakey = &object->certificate->key;
	obj2->certificate_object = cert;
        obj2->certificate_info = (struct sc_pkcs15_cert_info*) cert->data;
	pool_insert(&slot->object_pool, obj2, NULL);

	/* Mark as seen */
	cert->flags |= SC_PKCS15_CO_FLAG_OBJECT_SEEN;

        return object;
}

static struct pkcs15_prkey_object *pkcs15_add_prkey_object(struct sc_pkcs11_slot *slot,
							   struct sc_pkcs15_card *card,
							   struct sc_pkcs15_object *prkey,
							   struct sc_pkcs15_object **certs,
                                                           int cert_count
							  )
{
	struct pkcs15_prkey_object *object;
        int i;

        object = (struct pkcs15_prkey_object*) malloc(sizeof(struct pkcs15_prkey_object));
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

        return object;
}

static CK_RV pkcs15_create_tokens(struct sc_pkcs11_card *p11card)
{
        struct sc_pkcs15_card *card = (struct sc_pkcs15_card*) p11card->fw_data;
	struct sc_pkcs11_slot *slot;

	struct sc_pkcs15_object
		*auths[SC_PKCS15_MAX_PINS],
		*certs[SC_PKCS15_MAX_CERTS],
		*prkeys[SC_PKCS15_MAX_PRKEYS];

	int i, j, rv, reader = p11card->reader;
        int auth_count, cert_count, prkey_count;

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

	for (i = 0; i < auth_count; i++) {
		char tmp[33];
                struct sc_pkcs15_pin_info *pin_info;

		rv = slot_allocate(&slot, p11card);
		if (rv != CKR_OK)
			return rv;

		pkcs15_init_token_info(card, &slot->token_info);
		slot->fw_data = auths[i];

                pin_info = (struct sc_pkcs15_pin_info*) auths[i]->data;

		snprintf(tmp, sizeof(tmp), "%s (%s)", card->label, auths[i]->label);
		strcpy_bp(slot->token_info.label, tmp, 32);

		if (pin_info->magic == SC_PKCS15_PIN_MAGIC) {
			slot->token_info.ulMaxPinLen = pin_info->stored_length;
			slot->token_info.ulMinPinLen = pin_info->min_length;
		} else {
			/* choose reasonable defaults */
			slot->token_info.ulMaxPinLen = 8;
			slot->token_info.ulMinPinLen = 4;
		}
		slot->token_info.flags = CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED;

		debug(context, "Initialized token '%s'\n", tmp);

		/* Add all the private keys related to this pin */
		for (j=0; j < prkey_count; j++) {
			if (sc_pkcs15_compare_id(&pin_info->auth_id,
						 &prkeys[j]->auth_id)) {
                                debug(context, "Adding private key %d to PIN %d\n", j, i);
				pkcs15_add_prkey_object(slot, card, prkeys[j], certs, cert_count);
			}
		}
	}

        /* Add a virtual slot without pin protection */
	rv = slot_allocate(&slot, p11card);
	if (rv != CKR_OK)
		return rv;

	pkcs15_init_token_info(card, &slot->token_info);

	strcpy_bp(slot->token_info.label, card->label, 32);
	slot->token_info.ulMaxPinLen = 8;
	slot->token_info.ulMinPinLen = 4;
	slot->token_info.flags = 0;

	/* Add all the remaining private keys */
	for (j=0; j < prkey_count; j++) {
		if (!(prkeys[j]->flags & SC_PKCS15_CO_FLAG_OBJECT_SEEN)) {
                        debug(context, "Private key %d was not seen previously\n", j);
			pkcs15_add_prkey_object(slot, card, prkeys[j], certs, cert_count);
		}
	}

	/* Add all the remaining certificates */
	for (j=0; j < cert_count; j++) {
		if (!(certs[j]->flags & SC_PKCS15_CO_FLAG_OBJECT_SEEN)) {
                        debug(context, "Certificate %d was not seen previously\n", j);
			pkcs15_add_cert_object(slot, card, certs[j]);
		}
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

	rc = sc_pkcs15_verify_pin(card, pin, pPin, ulPinLen);
        debug(context, "PIN verification returned %d\n", rc);
	return sc_to_cryptoki_error(rc, p11card->reader);
}

static CK_RV pkcs15_logout(struct sc_pkcs11_card *p11card, void *fw_token)
{
        return CKR_OK;
}

struct sc_pkcs11_framework_ops framework_pkcs15 = {
	pkcs15_bind,
	pkcs15_unbind,
	pkcs15_create_tokens,
	pkcs15_release_token,
	pkcs15_get_mechanism_list,
	pkcs15_get_mechanism_info,
	pkcs15_login,
        pkcs15_logout
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
        /*
	case CKA_SUBJECT:
	case CKA_ISSUER:
	case CKA_SERIAL_NUMBER:
	break;
	*/
	default:
                return CKR_ATTRIBUTE_TYPE_INVALID;
	}

        return CKR_OK;
}

struct sc_pkcs11_object_ops pkcs15_cert_ops = {
	pkcs15_cert_release,
        NULL,
	pkcs15_cert_get_attribute,
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
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = TRUE;
                break;
	case CKA_MODIFIABLE:
	case CKA_DERIVE:
	case CKA_DECRYPT:
	case CKA_SIGN_RECOVER:
	case CKA_UNWRAP:
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
		check_attribute_buffer(attr, prkey->cert_object->certificate->key.modulus_len);
		memcpy(attr->pValue,
		       prkey->cert_object->certificate->key.modulus,
		       prkey->cert_object->certificate->key.modulus_len);
                break;
	case CKA_PUBLIC_EXPONENT:
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

	switch (pMechanism->mechanism) {
	case CKM_RSA_PKCS:
		break;
	case CKM_SHA1_RSA_PKCS:
		flags = SC_PKCS15_HASH_SHA1;
		break;
	default:
                return CKR_MECHANISM_INVALID;
	}

        debug(context, "Selected flags %X. Now computing signature. %d bytes reserved.\n", flags, *pulDataLen);
	rv = sc_pkcs15_compute_signature((struct sc_pkcs15_card*) ses->slot->card->fw_data,
					 prkey->prkey_info,
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

struct sc_pkcs11_object_ops pkcs15_prkey_ops = {
	NULL,
	NULL,
	pkcs15_prkey_get_attribute,
	NULL,
	NULL,
        pkcs15_prkey_sign
};

/*
 * PKCS#15 RSA Public Key Object
 */

CK_RV pkcs15_pubkey_get_attribute(struct sc_pkcs11_session *session,
				void *object,
				CK_ATTRIBUTE_PTR attr)
{
	struct pkcs15_pubkey_object *pubkey = (struct pkcs15_pubkey_object*) object;
	CK_ULONG	mask, bits, word, j, n;
	CK_BYTE		exponent[4];

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
		check_attribute_buffer(attr, pubkey->rsakey->modulus_len);
		memcpy(attr->pValue,
		       pubkey->rsakey->modulus,
		       pubkey->rsakey->modulus_len);
		break;
	case CKA_MODULUS_BITS:
		bits = pubkey->rsakey->modulus_len * 8;
		for (mask = 0x80; mask; mask >>= 1, bits--) {
			if (pubkey->rsakey->modulus[0] & mask)
				break;
		}
		check_attribute_buffer(attr, sizeof(bits));
		*(CK_ULONG *) attr->pValue = bits;
		break;
	case CKA_PUBLIC_EXPONENT:
		word = pubkey->rsakey->exponent;
		for (j = 0, n = 4; j < n; word <<= 8) {
			if ((word & 0xFF000000) || j)
				exponent[j++] = word >> 24;
			else
				n--;
		}
		check_attribute_buffer(attr, n);
		memcpy(attr->pValue, exponent, n);
		break;
	default:
                return CKR_ATTRIBUTE_TYPE_INVALID;
	}

        return CKR_OK;
}

struct sc_pkcs11_object_ops pkcs15_pubkey_ops = {
	NULL,
	NULL,
	pkcs15_pubkey_get_attribute,
	NULL,
	NULL,
        NULL
};


