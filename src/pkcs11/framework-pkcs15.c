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

struct pkcs15_cert_object {
	struct sc_pkcs11_object object;
	struct sc_pkcs15_cert_info *cert_info;
        struct sc_pkcs15_cert *cert;
};

struct pkcs15_prkey_object {
	struct sc_pkcs11_object object;
	struct sc_pkcs15_prkey_info *prkey_info;
        struct pkcs15_cert_object *cert_object;
};


/* PKCS#15 Framework */

static CK_RV pkcs15_bind(struct sc_pkcs11_card *p11card)
{
	int rc = sc_pkcs15_bind(p11card->card,
				(struct sc_pkcs15_card**) &p11card->fw_data);
	debug(context, "Binding to PKCS#15, rc=%d\n", rc);
        return sc_to_cryptoki_error(rc, p11card->card->reader);
}

static CK_RV pkcs15_unbind(struct sc_pkcs11_card *p11card)
{
        struct sc_pkcs15_card *card = (struct sc_pkcs15_card*) p11card->fw_data;
	int rc = sc_pkcs15_unbind(card);
        return sc_to_cryptoki_error(rc, card->card->reader);
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
				   struct sc_pkcs15_cert_info *cert)
{
	struct pkcs15_cert_object *object;

        object = (struct pkcs15_cert_object*) malloc(sizeof(struct pkcs15_cert_object));
	object->object.ops = &pkcs15_cert_ops;
	object->cert_info = cert;
	sc_pkcs15_read_certificate(card, cert, &object->cert);

	pool_insert(&slot->object_pool, object, NULL);

	/* Mark as seen */
	cert->com_attr.flags |= SC_PKCS15_CO_FLAG_OBJECT_SEEN;

        return object;
}

static struct pkcs15_prkey_object *pkcs15_add_prkey_object(struct sc_pkcs11_slot *slot,
                                    struct sc_pkcs15_card *card,
				    struct sc_pkcs15_prkey_info *prkey)
{
	struct pkcs15_prkey_object *object;
        int i;

        object = (struct pkcs15_prkey_object*) malloc(sizeof(struct pkcs15_prkey_object));
	object->object.ops = &pkcs15_prkey_ops;
        object->prkey_info = prkey;
	pool_insert(&slot->object_pool, object, NULL);

	/* Mark as seen */
        prkey->com_attr.flags |= SC_PKCS15_CO_FLAG_OBJECT_SEEN;

	/* Also add the related certificate if found */
	for (i=0; i<card->cert_count; i++) {
		if (sc_pkcs15_compare_id(&prkey->id,
					 &card->cert_info[i].id)) {
			debug(context, "Adding certificate %d relating to private key\n", i);
                        object->cert_object = pkcs15_add_cert_object(slot, card, &card->cert_info[i]);
                        break;
		}
	}

        return object;
}

static CK_RV pkcs15_create_tokens(struct sc_pkcs11_card *p11card)
{
        struct sc_pkcs15_card *card = (struct sc_pkcs15_card*) p11card->fw_data;
	struct sc_pkcs11_slot *slot;
        int i, j, rv, reader = card->card->reader;

	debug(context, "Enumerating PINS\n");
	rv = sc_pkcs15_enum_pins(card);
	if (rv < 0)
                return sc_to_cryptoki_error(rv, reader);

	debug(context, "Enumerating certs\n");
	rv = sc_pkcs15_enum_certificates(card);
	if (rv < 0)
                return sc_to_cryptoki_error(rv, reader);

	debug(context, "Enumerating private keys\n");
	rv = sc_pkcs15_enum_private_keys(card);
 	if (rv < 0)
                return sc_to_cryptoki_error(rv, reader);

	for (i = 0; i < card->pin_count; i++) {
                char tmp[33];

		rv = slot_allocate(&slot, p11card);
		if (rv != CKR_OK)
			return rv;

		pkcs15_init_token_info(card, &slot->token_info);
                slot->fw_data = &card->pin_info[i];

		snprintf(tmp, sizeof(tmp), "%s (%s)", card->label, card->pin_info[i].com_attr.label);
		strcpy_bp(slot->token_info.label, tmp, 32);

		if (card->pin_info[i].magic == SC_PKCS15_PIN_MAGIC) {
			slot->token_info.ulMaxPinLen = card->pin_info[i].stored_length;
			slot->token_info.ulMinPinLen = card->pin_info[i].min_length;
		} else {
			/* choose reasonable defaults */
			slot->token_info.ulMaxPinLen = 8;
			slot->token_info.ulMinPinLen = 4;
		}
		slot->token_info.flags = CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED;

		debug(context, "Initialized token '%s'\n", tmp);

		/* Add all the private keys related to this pin */
		for (j=0; j<card->prkey_count; j++) {
			if (sc_pkcs15_compare_id(&card->pin_info[i].auth_id,
						 &card->prkey_info[j].com_attr.auth_id)) {
                                debug(context, "Adding private key %d to PIN %d\n", j, i);
				pkcs15_add_prkey_object(slot, card, &card->prkey_info[j]);
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
	for (j=0; j<card->prkey_count; j++) {
		if (!(card->prkey_info[j].com_attr.flags & SC_PKCS15_CO_FLAG_OBJECT_SEEN)) {
                        debug(context, "Private key %d was not seen previously\n", j);
			pkcs15_add_prkey_object(slot, card, &card->prkey_info[j]);
		}
	}

	/* Add all the remaining certificates */
	for (j=0; j<card->cert_count; j++) {
		if (!(card->cert_info[j].com_attr.flags & SC_PKCS15_CO_FLAG_OBJECT_SEEN)) {
                        debug(context, "Certificate %d was not seen previously\n", j);
			pkcs15_add_cert_object(slot, card, &card->cert_info[j]);
		}
	}


/*
	for (i = 0; c < card->cert_count; c++) {
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
	*/


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
	struct sc_pkcs15_pin_info *pin = (struct sc_pkcs15_pin_info*) fw_token;

	rc = sc_pkcs15_verify_pin(card, pin, pPin, ulPinLen);
	return sc_to_cryptoki_error(rc, card->card->reader);
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
	sc_pkcs15_free_certificate(cert->cert);
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
		check_attribute_buffer(attr, strlen(cert->cert_info->com_attr.label));
                memcpy(attr->pValue, cert->cert_info->com_attr.label, strlen(cert->cert_info->com_attr.label));
                break;
	case CKA_CERTIFICATE_TYPE:
		check_attribute_buffer(attr, sizeof(CK_CERTIFICATE_TYPE));
                *(CK_CERTIFICATE_TYPE*)attr->pValue = CKC_X_509;
		break;
	case CKA_ID:
		check_attribute_buffer(attr, cert->cert_info->id.len);
		memcpy(attr->pValue, cert->cert_info->id.value, cert->cert_info->id.len);
                break;
	case CKA_TRUSTED:
		check_attribute_buffer(attr, sizeof(CK_BBOOL));
		*(CK_BBOOL*)attr->pValue = cert->cert_info->authority?TRUE:FALSE;
                break;
	case CKA_VALUE:
		check_attribute_buffer(attr, cert->cert->data_len);
		memcpy(attr->pValue, cert->cert->data, cert->cert->data_len);
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
	case CKA_PRIVATE:
	case CKA_LOCAL:
	case CKA_SENSITIVE:
	case CKA_ALWAYS_SENSITIVE:
	case CKA_NEVER_EXTRACTABLE:
	case CKA_SIGN:
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
		check_attribute_buffer(attr, strlen(prkey->prkey_info->com_attr.label));
                memcpy(attr->pValue, prkey->prkey_info->com_attr.label, strlen(prkey->prkey_info->com_attr.label));
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
		check_attribute_buffer(attr, prkey->cert_object->cert->key.modulus_len);
		memcpy(attr->pValue,
		       prkey->cert_object->cert->key.modulus,
		       prkey->cert_object->cert->key.modulus_len);
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

