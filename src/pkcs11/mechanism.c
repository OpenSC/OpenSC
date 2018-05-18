/*
 * Generic handling of PKCS11 mechanisms
 *
 * Copyright (C) 2002 Olaf Kirch <okir@suse.de>
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

/* Also used for verification data */
struct hash_signature_info {
	CK_MECHANISM_TYPE	mech;
	CK_MECHANISM_TYPE	hash_mech;
	CK_MECHANISM_TYPE	sign_mech;
	sc_pkcs11_mechanism_type_t *hash_type;
	sc_pkcs11_mechanism_type_t *sign_type;
};

/* Also used for verification and decryption data */
struct signature_data {
	struct sc_pkcs11_object *key;
	struct hash_signature_info *info;
	sc_pkcs11_operation_t *	md;
	CK_BYTE			buffer[4096/8];
	unsigned int		buffer_len;
};

/*
 * Register a mechanism
 */
CK_RV
sc_pkcs11_register_mechanism(struct sc_pkcs11_card *p11card,
				sc_pkcs11_mechanism_type_t *mt)
{
	sc_pkcs11_mechanism_type_t **p;

	if (mt == NULL)
		return CKR_HOST_MEMORY;

	p = (sc_pkcs11_mechanism_type_t **) realloc(p11card->mechanisms,
			(p11card->nmechanisms + 2) * sizeof(*p));
	if (p == NULL)
		return CKR_HOST_MEMORY;
	p11card->mechanisms = p;
	p[p11card->nmechanisms++] = mt;
	p[p11card->nmechanisms] = NULL;
	return CKR_OK;
}

/*
 * Look up a mechanism
 */
sc_pkcs11_mechanism_type_t *
sc_pkcs11_find_mechanism(struct sc_pkcs11_card *p11card, CK_MECHANISM_TYPE mech, unsigned int flags)
{
	sc_pkcs11_mechanism_type_t *mt;
	unsigned int n;

	for (n = 0; n < p11card->nmechanisms; n++) {
		mt = p11card->mechanisms[n];
		if (mt && mt->mech == mech && ((mt->mech_info.flags & flags) == flags))
			return mt;
	}
	return NULL;
}

/*
 * Query mechanisms.
 * All of this is greatly simplified by having the framework
 * register all supported mechanisms at initialization
 * time.
 */
CK_RV
sc_pkcs11_get_mechanism_list(struct sc_pkcs11_card *p11card,
				CK_MECHANISM_TYPE_PTR pList,
				CK_ULONG_PTR pulCount)
{
	sc_pkcs11_mechanism_type_t *mt;
	unsigned int n, count = 0;
	int rv;

	if (!p11card)
		return CKR_TOKEN_NOT_PRESENT;

	for (n = 0; n < p11card->nmechanisms; n++) {
		if (!(mt = p11card->mechanisms[n]))
			continue;
		if (pList && count < *pulCount)
			pList[count] = mt->mech;
		count++;
	}

	rv = CKR_OK;
	if (pList && count > *pulCount)
		rv = CKR_BUFFER_TOO_SMALL;
	*pulCount = count;
	return rv;
}

CK_RV
sc_pkcs11_get_mechanism_info(struct sc_pkcs11_card *p11card,
			CK_MECHANISM_TYPE mechanism,
			CK_MECHANISM_INFO_PTR pInfo)
{
	sc_pkcs11_mechanism_type_t *mt;

	if (!(mt = sc_pkcs11_find_mechanism(p11card, mechanism, 0)))
		return CKR_MECHANISM_INVALID;
	memcpy(pInfo, &mt->mech_info, sizeof(*pInfo));
	return CKR_OK;
}

/*
 * Create/destroy operation handle
 */
sc_pkcs11_operation_t *
sc_pkcs11_new_operation(sc_pkcs11_session_t *session,
			sc_pkcs11_mechanism_type_t *type)
{
	sc_pkcs11_operation_t *res;

	res = calloc(1, type->obj_size);
	if (res) {
		res->session = session;
		res->type = type;
	}
	return res;
}

void
sc_pkcs11_release_operation(sc_pkcs11_operation_t **ptr)
{
	sc_pkcs11_operation_t *operation = *ptr;

	if (!operation)
		return;
	if (operation->type && operation->type->release)
		operation->type->release(operation);
	memset(operation, 0, sizeof(*operation));
	free(operation);
	*ptr = NULL;
}

CK_RV
sc_pkcs11_md_init(struct sc_pkcs11_session *session,
			CK_MECHANISM_PTR pMechanism)
{
	struct sc_pkcs11_card *p11card;
	sc_pkcs11_operation_t *operation;
	sc_pkcs11_mechanism_type_t *mt;
	int rv;

	LOG_FUNC_CALLED(context);
	if (!session || !session->slot || !(p11card = session->slot->p11card))
		LOG_FUNC_RETURN(context, CKR_ARGUMENTS_BAD);

	/* See if we support this mechanism type */
	mt = sc_pkcs11_find_mechanism(p11card, pMechanism->mechanism, CKF_DIGEST);
	if (mt == NULL)
		LOG_FUNC_RETURN(context, CKR_MECHANISM_INVALID);

	rv = session_start_operation(session, SC_PKCS11_OPERATION_DIGEST, mt, &operation);
	if (rv != CKR_OK)
		LOG_FUNC_RETURN(context, rv);

	memcpy(&operation->mechanism, pMechanism, sizeof(CK_MECHANISM));

	rv = mt->md_init(operation);

	if (rv != CKR_OK)
		session_stop_operation(session, SC_PKCS11_OPERATION_DIGEST);

	LOG_FUNC_RETURN(context, rv);
}

CK_RV
sc_pkcs11_md_update(struct sc_pkcs11_session *session,
			CK_BYTE_PTR pData, CK_ULONG ulDataLen)
{
	sc_pkcs11_operation_t *op;
	int rv;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_DIGEST, &op);
	if (rv != CKR_OK)
		goto done;

	rv = op->type->md_update(op, pData, ulDataLen);

done:
	if (rv != CKR_OK)
		session_stop_operation(session, SC_PKCS11_OPERATION_DIGEST);

	LOG_FUNC_RETURN(context, rv);
}

CK_RV
sc_pkcs11_md_final(struct sc_pkcs11_session *session,
			CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	sc_pkcs11_operation_t *op;
	CK_RV rv;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_DIGEST, &op);
	if (rv != CKR_OK)
		LOG_FUNC_RETURN(context, rv);

	/* This is a request for the digest length */
	if (pData == NULL)
		*pulDataLen = 0;

	rv = op->type->md_final(op, pData, pulDataLen);
	if (rv == CKR_BUFFER_TOO_SMALL)
		LOG_FUNC_RETURN(context,  pData == NULL ? CKR_OK : CKR_BUFFER_TOO_SMALL);

	session_stop_operation(session, SC_PKCS11_OPERATION_DIGEST);
	LOG_FUNC_RETURN(context, rv);
}

/*
 * Initialize a signing context. When we get here, we know
 * the key object is capable of signing _something_
 */
CK_RV
sc_pkcs11_sign_init(struct sc_pkcs11_session *session, CK_MECHANISM_PTR pMechanism,
		    struct sc_pkcs11_object *key, CK_MECHANISM_TYPE key_type)
{
	struct sc_pkcs11_card *p11card;
	sc_pkcs11_operation_t *operation;
	sc_pkcs11_mechanism_type_t *mt;
	int rv;

	LOG_FUNC_CALLED(context);
	if (!session || !session->slot || !(p11card = session->slot->p11card))
		LOG_FUNC_RETURN(context, CKR_ARGUMENTS_BAD);

	/* See if we support this mechanism type */
	sc_log(context, "mechanism 0x%lX, key-type 0x%lX",
	       pMechanism->mechanism, key_type);
	mt = sc_pkcs11_find_mechanism(p11card, pMechanism->mechanism, CKF_SIGN);
	if (mt == NULL)
		LOG_FUNC_RETURN(context, CKR_MECHANISM_INVALID);

	/* See if compatible with key type */
	if (mt->key_type != key_type)
		LOG_FUNC_RETURN(context, CKR_KEY_TYPE_INCONSISTENT);

	rv = session_start_operation(session, SC_PKCS11_OPERATION_SIGN, mt, &operation);
	if (rv != CKR_OK)
		LOG_FUNC_RETURN(context, rv);

	memcpy(&operation->mechanism, pMechanism, sizeof(CK_MECHANISM));
	rv = mt->sign_init(operation, key);
	if (rv != CKR_OK)
		session_stop_operation(session, SC_PKCS11_OPERATION_SIGN);

	LOG_FUNC_RETURN(context, rv);
}

CK_RV
sc_pkcs11_sign_update(struct sc_pkcs11_session *session,
		      CK_BYTE_PTR pData, CK_ULONG ulDataLen)
{
	sc_pkcs11_operation_t *op;
	int rv;

	LOG_FUNC_CALLED(context);
	rv = session_get_operation(session, SC_PKCS11_OPERATION_SIGN, &op);
	if (rv != CKR_OK)
		LOG_FUNC_RETURN(context, rv);

	if (op->type->sign_update == NULL) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto done;
	}

	rv = op->type->sign_update(op, pData, ulDataLen);

done:
	if (rv != CKR_OK)
		session_stop_operation(session, SC_PKCS11_OPERATION_SIGN);

	LOG_FUNC_RETURN(context, rv);
}

CK_RV
sc_pkcs11_sign_final(struct sc_pkcs11_session *session,
		     CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	sc_pkcs11_operation_t *op;
	int rv;

	LOG_FUNC_CALLED(context);
	rv = session_get_operation(session, SC_PKCS11_OPERATION_SIGN, &op);
	if (rv != CKR_OK)
		LOG_FUNC_RETURN(context, rv);

	/* Bail out for signature mechanisms that don't do hashing */
	if (op->type->sign_final == NULL) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto done;
	}

	rv = op->type->sign_final(op, pSignature, pulSignatureLen);

done:
	if (rv != CKR_BUFFER_TOO_SMALL && pSignature != NULL)
		session_stop_operation(session, SC_PKCS11_OPERATION_SIGN);

	LOG_FUNC_RETURN(context, rv);
}

CK_RV
sc_pkcs11_sign_size(struct sc_pkcs11_session *session, CK_ULONG_PTR pLength)
{
	sc_pkcs11_operation_t *op;
	int rv;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_SIGN, &op);
	if (rv != CKR_OK)
		LOG_FUNC_RETURN(context, rv);

	/* Bail out for signature mechanisms that don't do hashing */
	if (op->type->sign_size == NULL) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto done;
	}

	rv = op->type->sign_size(op, pLength);

done:
	if (rv != CKR_OK)
		session_stop_operation(session, SC_PKCS11_OPERATION_SIGN);

	LOG_FUNC_RETURN(context, rv);
}

/*
 * Initialize a signature operation
 */
static CK_RV
sc_pkcs11_signature_init(sc_pkcs11_operation_t *operation,
		struct sc_pkcs11_object *key)
{
	struct hash_signature_info *info;
	struct signature_data *data;
	CK_RV rv;
	int can_do_it = 0;

	LOG_FUNC_CALLED(context);
	if (!(data = calloc(1, sizeof(*data))))
		LOG_FUNC_RETURN(context, CKR_HOST_MEMORY);
	data->info = NULL;
	data->key = key;

	if (key->ops->can_do)   {
		rv = key->ops->can_do(operation->session, key, operation->type->mech, CKF_SIGN);
		if (rv == CKR_OK)   {
			/* Mechanism recognised and can be performed by pkcs#15 card */
			can_do_it = 1;
		}
		else if (rv == CKR_FUNCTION_NOT_SUPPORTED)   {
			/* Mechanism not recognised by pkcs#15 card */
			can_do_it = 0;
		}
		else  {
			/* Mechanism recognised but cannot be performed by pkcs#15 card, or some general error. */
			free(data);
			LOG_FUNC_RETURN(context, rv);
		}
	}

	/* If this is a signature with hash operation,
	 * and card cannot perform itself signature with hash operation,
	 * set up the hash operation */
	info = (struct hash_signature_info *) operation->type->mech_data;
	if (info != NULL && !can_do_it) {
		/* Initialize hash operation */

		data->md = sc_pkcs11_new_operation(operation->session, info->hash_type);
		if (data->md == NULL)
			rv = CKR_HOST_MEMORY;
		else
			rv = info->hash_type->md_init(data->md);
		if (rv != CKR_OK) {
			sc_pkcs11_release_operation(&data->md);
			free(data);
			LOG_FUNC_RETURN(context, rv);
		}
		data->info = info;
	}

	operation->priv_data = data;
	LOG_FUNC_RETURN(context, CKR_OK);
}

static CK_RV
sc_pkcs11_signature_update(sc_pkcs11_operation_t *operation,
		CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	struct signature_data *data;

	LOG_FUNC_CALLED(context);
	sc_log(context, "data part length %li", ulPartLen);
	data = (struct signature_data *) operation->priv_data;
	if (data->md) {
		CK_RV rv = data->md->type->md_update(data->md, pPart, ulPartLen);
		LOG_FUNC_RETURN(context, rv);
	}

	/* This signature mechanism operates on the raw data */
	if (data->buffer_len + ulPartLen > sizeof(data->buffer))
		LOG_FUNC_RETURN(context, CKR_DATA_LEN_RANGE);
	memcpy(data->buffer + data->buffer_len, pPart, ulPartLen);
	data->buffer_len += ulPartLen;
	sc_log(context, "data length %u", data->buffer_len);
	LOG_FUNC_RETURN(context, CKR_OK);
}

static CK_RV
sc_pkcs11_signature_final(sc_pkcs11_operation_t *operation,
		CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	struct signature_data *data;
	CK_RV rv;

	LOG_FUNC_CALLED(context);
	data = (struct signature_data *) operation->priv_data;
	sc_log(context, "data length %u", data->buffer_len);
	if (data->md) {
		sc_pkcs11_operation_t	*md = data->md;
		CK_ULONG len = sizeof(data->buffer);

		rv = md->type->md_final(md, data->buffer, &len);
		if (rv == CKR_BUFFER_TOO_SMALL)
			rv = CKR_FUNCTION_FAILED;
		if (rv != CKR_OK)
			LOG_FUNC_RETURN(context, rv);
		data->buffer_len = len;
	}

	sc_log(context, "%u bytes to sign", data->buffer_len);
	rv = data->key->ops->sign(operation->session, data->key, &operation->mechanism,
			data->buffer, data->buffer_len, pSignature, pulSignatureLen);
	LOG_FUNC_RETURN(context, rv);
}

static CK_RV
sc_pkcs11_signature_size(sc_pkcs11_operation_t *operation, CK_ULONG_PTR pLength)
{
	struct sc_pkcs11_object *key;
	CK_ATTRIBUTE attr = { CKA_MODULUS_BITS, pLength, sizeof(*pLength) };
	CK_KEY_TYPE key_type;
	CK_ATTRIBUTE attr_key_type = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };
	CK_RV rv;

	key = ((struct signature_data *) operation->priv_data)->key;
	/*
	 * EC and GOSTR do not have CKA_MODULUS_BITS attribute.
	 * But other code in framework treats them as if they do.
	 * So should do switch(key_type)
	 * and then get what ever attributes are needed.
	 */
	rv = key->ops->get_attribute(operation->session, key, &attr_key_type);
	if (rv == CKR_OK) {
		switch(key_type) {
			case CKK_RSA:
				rv = key->ops->get_attribute(operation->session, key, &attr);
				/* convert bits to bytes */
				if (rv == CKR_OK)
					*pLength = (*pLength + 7) / 8;
				break;
			case CKK_EC:
				/* TODO: -DEE we should use something other then CKA_MODULUS_BITS... */
				rv = key->ops->get_attribute(operation->session, key, &attr);
				*pLength = ((*pLength + 7)/8) * 2 ; /* 2*nLen in bytes */
				break;
			case CKK_GOSTR3410:
				rv = key->ops->get_attribute(operation->session, key, &attr);
				if (rv == CKR_OK)
					*pLength = (*pLength + 7) / 8 * 2;
				break;
			default:
				rv = CKR_MECHANISM_INVALID;
		}
	}

	LOG_FUNC_RETURN(context, rv);
}

static void
sc_pkcs11_signature_release(sc_pkcs11_operation_t *operation)
{
	struct signature_data *data;

	data = (struct signature_data *) operation->priv_data;
	if (!data)
	    return;
	sc_pkcs11_release_operation(&data->md);
	memset(data, 0, sizeof(*data));
	free(data);
}

#ifdef ENABLE_OPENSSL
/*
 * Initialize a verify context. When we get here, we know
 * the key object is capable of verifying _something_
 */
CK_RV
sc_pkcs11_verif_init(struct sc_pkcs11_session *session, CK_MECHANISM_PTR pMechanism,
		struct sc_pkcs11_object *key, CK_MECHANISM_TYPE key_type)
{
	struct sc_pkcs11_card *p11card;
	sc_pkcs11_operation_t *operation;
	sc_pkcs11_mechanism_type_t *mt;
	int rv;

	if (!session || !session->slot
	 || !(p11card = session->slot->p11card))
		return CKR_ARGUMENTS_BAD;

	/* See if we support this mechanism type */
	mt = sc_pkcs11_find_mechanism(p11card, pMechanism->mechanism, CKF_VERIFY);
	if (mt == NULL)
		return CKR_MECHANISM_INVALID;

	/* See if compatible with key type */
	if (mt->key_type != key_type)
		return CKR_KEY_TYPE_INCONSISTENT;

	rv = session_start_operation(session, SC_PKCS11_OPERATION_VERIFY, mt, &operation);
	if (rv != CKR_OK)
		return rv;

	memcpy(&operation->mechanism, pMechanism, sizeof(CK_MECHANISM));
	rv = mt->verif_init(operation, key);

	if (rv != CKR_OK)
		session_stop_operation(session, SC_PKCS11_OPERATION_VERIFY);

	return rv;

}

CK_RV
sc_pkcs11_verif_update(struct sc_pkcs11_session *session,
		      CK_BYTE_PTR pData, CK_ULONG ulDataLen)
{
	sc_pkcs11_operation_t *op;
	int rv;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_VERIFY, &op);
	if (rv != CKR_OK)
		return rv;

	if (op->type->verif_update == NULL) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto done;
	}

	rv = op->type->verif_update(op, pData, ulDataLen);

done:
	if (rv != CKR_OK)
		session_stop_operation(session, SC_PKCS11_OPERATION_VERIFY);

	return rv;
}

CK_RV
sc_pkcs11_verif_final(struct sc_pkcs11_session *session,
		     CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	sc_pkcs11_operation_t *op;
	int rv;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_VERIFY, &op);
	if (rv != CKR_OK)
		return rv;

	if (op->type->verif_final == NULL) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto done;
	}

	rv = op->type->verif_final(op, pSignature, ulSignatureLen);

done:
	session_stop_operation(session, SC_PKCS11_OPERATION_VERIFY);
	return rv;
}

/*
 * Initialize a verify operation
 */
static CK_RV
sc_pkcs11_verify_init(sc_pkcs11_operation_t *operation,
		    struct sc_pkcs11_object *key)
{
	struct hash_signature_info *info;
	struct signature_data *data;
	int rv;

	if (!(data = calloc(1, sizeof(*data))))
		return CKR_HOST_MEMORY;

	data->info = NULL;
	data->key = key;

	if (key->ops->can_do)   {
		rv = key->ops->can_do(operation->session, key, operation->type->mech, CKF_SIGN);
		if ((rv == CKR_OK) || (rv == CKR_FUNCTION_NOT_SUPPORTED))   {
			/* Mechanism recognized and can be performed by pkcs#15 card or algorithm references not supported */
		}
		else {
			/* Mechanism cannot be performed by pkcs#15 card, or some general error. */
			free(data);
			LOG_FUNC_RETURN(context, rv);
		}
	}

	/* If this is a verify with hash operation, set up the
	 * hash operation */
	info = (struct hash_signature_info *) operation->type->mech_data;
	if (info != NULL) {
		/* Initialize hash operation */
		data->md = sc_pkcs11_new_operation(operation->session,
						   info->hash_type);
		if (data->md == NULL)
			rv = CKR_HOST_MEMORY;
		else
			rv = info->hash_type->md_init(data->md);
		if (rv != CKR_OK) {
			sc_pkcs11_release_operation(&data->md);
			free(data);
			return rv;
		}
		data->info = info;
	}

	operation->priv_data = data;
	return CKR_OK;
}

static CK_RV
sc_pkcs11_verify_update(sc_pkcs11_operation_t *operation,
		    CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	struct signature_data *data;

	data = (struct signature_data *) operation->priv_data;
	if (data->md) {
		sc_pkcs11_operation_t	*md = data->md;

		return md->type->md_update(md, pPart, ulPartLen);
	}

	/* This verification mechanism operates on the raw data */
	if (data->buffer_len + ulPartLen > sizeof(data->buffer))
		return CKR_DATA_LEN_RANGE;
	memcpy(data->buffer + data->buffer_len, pPart, ulPartLen);
	data->buffer_len += ulPartLen;
	return CKR_OK;
}

static CK_RV
sc_pkcs11_verify_final(sc_pkcs11_operation_t *operation,
			CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	struct signature_data *data;
	struct sc_pkcs11_object *key;
	unsigned char *pubkey_value = NULL;
	CK_KEY_TYPE key_type;
	CK_BYTE params[9 /* GOST_PARAMS_ENCODED_OID_SIZE */] = { 0 };
	CK_ATTRIBUTE attr = {CKA_VALUE, NULL, 0};
	CK_ATTRIBUTE attr_key_type = {CKA_KEY_TYPE, &key_type, sizeof(key_type)};
	CK_ATTRIBUTE attr_key_params = {CKA_GOSTR3410_PARAMS, &params, sizeof(params)};
	int rv;

	data = (struct signature_data *) operation->priv_data;

	if (pSignature == NULL)
		return CKR_ARGUMENTS_BAD;

	key = data->key;
	rv = key->ops->get_attribute(operation->session, key, &attr_key_type);
	if (rv != CKR_OK)
		return rv;

	if (key_type != CKK_GOSTR3410)
		attr.type = CKA_SPKI;
		

	rv = key->ops->get_attribute(operation->session, key, &attr);
	if (rv != CKR_OK)
		return rv;
	pubkey_value = calloc(1, attr.ulValueLen);
	if (!pubkey_value) {
		rv = CKR_HOST_MEMORY;
		goto done;
	}
	attr.pValue = pubkey_value;
	rv = key->ops->get_attribute(operation->session, key, &attr);
	if (rv != CKR_OK)
		goto done;

	if (key_type == CKK_GOSTR3410) {
		rv = key->ops->get_attribute(operation->session, key, &attr_key_params);
		if (rv != CKR_OK)
			goto done;
	}

	rv = sc_pkcs11_verify_data(pubkey_value, attr.ulValueLen,
		params, sizeof(params),
		operation->mechanism.mechanism, data->md,
		data->buffer, data->buffer_len, pSignature, ulSignatureLen);

done:
	free(pubkey_value);

	return rv;
}
#endif

/*
 * Initialize a decryption context. When we get here, we know
 * the key object is capable of decrypting _something_
 */
CK_RV
sc_pkcs11_decr_init(struct sc_pkcs11_session *session,
			CK_MECHANISM_PTR pMechanism,
			struct sc_pkcs11_object *key,
			CK_MECHANISM_TYPE key_type)
{
	struct sc_pkcs11_card *p11card;
	sc_pkcs11_operation_t *operation;
	sc_pkcs11_mechanism_type_t *mt;
	CK_RV rv;

	if (!session || !session->slot
	 || !(p11card = session->slot->p11card))
		return CKR_ARGUMENTS_BAD;

	/* See if we support this mechanism type */
	mt = sc_pkcs11_find_mechanism(p11card, pMechanism->mechanism, CKF_DECRYPT);
	if (mt == NULL)
		return CKR_MECHANISM_INVALID;

	/* See if compatible with key type */
	if (mt->key_type != key_type)
		return CKR_KEY_TYPE_INCONSISTENT;

	rv = session_start_operation(session, SC_PKCS11_OPERATION_DECRYPT, mt, &operation);
	if (rv != CKR_OK)
		return rv;

	memcpy(&operation->mechanism, pMechanism, sizeof(CK_MECHANISM));
	rv = mt->decrypt_init(operation, key);

	if (rv != CKR_OK)
		session_stop_operation(session, SC_PKCS11_OPERATION_DECRYPT);

	return rv;
}

CK_RV
sc_pkcs11_decr(struct sc_pkcs11_session *session,
		CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
		CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	sc_pkcs11_operation_t *op;
	int rv;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_DECRYPT, &op);
	if (rv != CKR_OK)
		return rv;

	rv = op->type->decrypt(op, pEncryptedData, ulEncryptedDataLen,
	                       pData, pulDataLen);

	if (rv != CKR_BUFFER_TOO_SMALL && pData != NULL)
		session_stop_operation(session, SC_PKCS11_OPERATION_DECRYPT);

	return rv;
}

/* Derive one key from another, and return results in created object */
CK_RV
sc_pkcs11_deri(struct sc_pkcs11_session *session,
	CK_MECHANISM_PTR pMechanism,
	struct sc_pkcs11_object * basekey,
	CK_KEY_TYPE key_type,
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hdkey,
	struct sc_pkcs11_object * dkey)
{

	struct sc_pkcs11_card *p11card;
	sc_pkcs11_operation_t *operation;
	sc_pkcs11_mechanism_type_t *mt;
	CK_BYTE_PTR keybuf = NULL;
	CK_ULONG ulDataLen = 0;
	CK_ATTRIBUTE template[] = {
		{CKA_VALUE, keybuf, 0}
	};

	CK_RV rv;


	if (!session || !session->slot
	 || !(p11card = session->slot->p11card))
		return CKR_ARGUMENTS_BAD;

	/* See if we support this mechanism type */
	mt = sc_pkcs11_find_mechanism(p11card, pMechanism->mechanism, CKF_DERIVE);
	if (mt == NULL)
		return CKR_MECHANISM_INVALID;

	/* See if compatible with key type */
	if (mt->key_type != key_type)
		return CKR_KEY_TYPE_INCONSISTENT;


	rv = session_start_operation(session, SC_PKCS11_OPERATION_DERIVE, mt, &operation);
	if (rv != CKR_OK)
		return rv;

	memcpy(&operation->mechanism, pMechanism, sizeof(CK_MECHANISM));

	/* Get the size of the data to be returned
	 * If the card could derive a key an leave it on the card
	 * then no data is returned.
	 * If the card returns the data, we will store it in the secret key CKA_VALUE
	 */

	ulDataLen = 0;
	rv = operation->type->derive(operation, basekey,
			pMechanism->pParameter, pMechanism->ulParameterLen,
			NULL, &ulDataLen);
	if (rv != CKR_OK)
		goto out;

	if (ulDataLen > 0)
		keybuf = calloc(1,ulDataLen);
	else
		keybuf = calloc(1,8); /* pass in  dummy buffer */

	if (!keybuf) {
		rv = CKR_HOST_MEMORY;
		goto out;
	}

	/* Now do the actual derivation */

	rv = operation->type->derive(operation, basekey,
	    pMechanism->pParameter, pMechanism->ulParameterLen,
	    keybuf, &ulDataLen);
	if (rv != CKR_OK)
	    goto out;


/* add the CKA_VALUE attribute to the template if it was returned
 * if not assume it is on the card...
 * But for now PIV with ECDH returns the generic key data
 * TODO need to support truncation, if CKA_VALUE_LEN < ulDataLem
 */
	if (ulDataLen > 0) {
	    template[0].pValue = keybuf;
	    template[0].ulValueLen = ulDataLen;

	    dkey->ops->set_attribute(session, dkey, &template[0]);

	    memset(keybuf,0,ulDataLen);
	}

out:
	session_stop_operation(session, SC_PKCS11_OPERATION_DERIVE);

	if (keybuf)
	    free(keybuf);
	return rv;
}


/*
 * Initialize a decrypt operation
 */
static CK_RV
sc_pkcs11_decrypt_init(sc_pkcs11_operation_t *operation,
			struct sc_pkcs11_object *key)
{
	struct signature_data *data;
	CK_RV rv;

	if (!(data = calloc(1, sizeof(*data))))
		return CKR_HOST_MEMORY;

	data->key = key;

	if (key->ops->can_do)   {
		rv = key->ops->can_do(operation->session, key, operation->type->mech, CKF_DECRYPT);
		if ((rv == CKR_OK) || (rv == CKR_FUNCTION_NOT_SUPPORTED))   {
			/* Mechanism recognized and can be performed by pkcs#15 card or algorithm references not supported */
		}
		else {
			/* Mechanism cannot be performed by pkcs#15 card, or some general error. */
			free(data);
			LOG_FUNC_RETURN(context, rv);
		}
	}

	operation->priv_data = data;
	return CKR_OK;
}

static CK_RV
sc_pkcs11_decrypt(sc_pkcs11_operation_t *operation,
		CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
		CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	struct signature_data *data;
	struct sc_pkcs11_object *key;

	data = (struct signature_data*) operation->priv_data;

	key = data->key;
	return key->ops->decrypt(operation->session,
				key, &operation->mechanism,
				pEncryptedData, ulEncryptedDataLen,
				pData, pulDataLen);
}

static CK_RV
sc_pkcs11_derive(sc_pkcs11_operation_t *operation,
	    struct sc_pkcs11_object *basekey,
	    CK_BYTE_PTR pmechParam, CK_ULONG ulmechParamLen,
	    CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{

	return basekey->ops->derive(operation->session,
		    basekey,
		    &operation->mechanism,
		    pmechParam, ulmechParamLen,
		    pData, pulDataLen);
}

/*
 * Create new mechanism type for a mechanism supported by
 * the card
 */
sc_pkcs11_mechanism_type_t *
sc_pkcs11_new_fw_mechanism(CK_MECHANISM_TYPE mech,
				CK_MECHANISM_INFO_PTR pInfo,
				CK_KEY_TYPE key_type,
				const void *priv_data,
				void (*free_priv_data)(const void *priv_data))
{
	sc_pkcs11_mechanism_type_t *mt;

	mt = calloc(1, sizeof(*mt));
	if (mt == NULL)
		return mt;
	mt->mech = mech;
	mt->mech_info = *pInfo;
	mt->key_type = key_type;
	mt->mech_data = priv_data;
	mt->free_mech_data = free_priv_data;
	mt->obj_size = sizeof(sc_pkcs11_operation_t);

	mt->release = sc_pkcs11_signature_release;

	if (pInfo->flags & CKF_SIGN) {
		mt->sign_init = sc_pkcs11_signature_init;
		mt->sign_update = sc_pkcs11_signature_update;
		mt->sign_final = sc_pkcs11_signature_final;
		mt->sign_size = sc_pkcs11_signature_size;
#ifdef ENABLE_OPENSSL
		mt->verif_init = sc_pkcs11_verify_init;
		mt->verif_update = sc_pkcs11_verify_update;
		mt->verif_final = sc_pkcs11_verify_final;
#endif
	}
	if (pInfo->flags & CKF_UNWRAP) {
		/* TODO */
	}
	if (pInfo->flags & CKF_DERIVE) {
		mt->derive = sc_pkcs11_derive;
	}
	if (pInfo->flags & CKF_DECRYPT) {
		mt->decrypt_init = sc_pkcs11_decrypt_init;
		mt->decrypt = sc_pkcs11_decrypt;
	}

	return mt;
}

/*
 * Register generic mechanisms
 */
CK_RV
sc_pkcs11_register_generic_mechanisms(struct sc_pkcs11_card *p11card)
{
#ifdef ENABLE_OPENSSL
	sc_pkcs11_register_openssl_mechanisms(p11card);
#endif
	return CKR_OK;
}

void free_info(const void *info)
{
	free((void *) info);
}

/*
 * Register a sign+hash algorithm derived from an algorithm supported
 * by the token + a software hash mechanism
 */
CK_RV
sc_pkcs11_register_sign_and_hash_mechanism(struct sc_pkcs11_card *p11card,
		CK_MECHANISM_TYPE mech,
		CK_MECHANISM_TYPE hash_mech,
		sc_pkcs11_mechanism_type_t *sign_type)
{
	sc_pkcs11_mechanism_type_t *hash_type, *new_type;
	struct hash_signature_info *info;
	CK_MECHANISM_INFO mech_info = sign_type->mech_info;
	CK_RV rv;

	if (!(hash_type = sc_pkcs11_find_mechanism(p11card, hash_mech, CKF_DIGEST)))
		return CKR_MECHANISM_INVALID;

	/* These hash-based mechs can only be used for sign/verify */
	mech_info.flags &= (CKF_SIGN | CKF_SIGN_RECOVER | CKF_VERIFY | CKF_VERIFY_RECOVER);

	info = calloc(1, sizeof(*info));
	if (!info)
		LOG_FUNC_RETURN(p11card->card->ctx, SC_ERROR_OUT_OF_MEMORY);

	info->mech = mech;
	info->sign_type = sign_type;
	info->hash_type = hash_type;
	info->sign_mech = sign_type->mech;
	info->hash_mech = hash_mech;

	new_type = sc_pkcs11_new_fw_mechanism(mech, &mech_info, sign_type->key_type, info, free_info);
	if (!new_type) {
		free_info(info);
		return CKR_HOST_MEMORY;
	}

	rv = sc_pkcs11_register_mechanism(p11card, new_type);
	if (CKR_OK != rv) {
		new_type->free_mech_data(new_type->mech_data);
		free(new_type);
	}

	return rv;
}
