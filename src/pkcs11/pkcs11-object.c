/*
 * pkcs11-object.c: PKCS#11 object management and handling functions
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

/* Pseudo mechanism for the Find operation */
static sc_pkcs11_mechanism_type_t	find_mechanism = {
	0, { 0 }, 0, 
	sizeof(struct sc_pkcs11_find_operation),
};

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,    /* the session's handle */
		     CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
		     CK_ULONG          ulCount,     /* attributes in template */
		     CK_OBJECT_HANDLE_PTR phObject) /* receives new object's handle. */
{
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_card *card;
	int rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;
	dump_template("C_CreateObject()", pTemplate, ulCount);

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	card = session->slot->card;
	if (card->framework->create_object == NULL)
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	else
		rv = card->framework->create_object(card, session->slot,
			pTemplate, ulCount, phObject);

out:	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE    hSession,    /* the session's handle */
		   CK_OBJECT_HANDLE     hObject,     /* the object's handle */
		   CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
		   CK_ULONG             ulCount,     /* attributes in template */
		   CK_OBJECT_HANDLE_PTR phNewObject) /* receives handle of copy */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession,  /* the session's handle */
		      CK_OBJECT_HANDLE  hObject)   /* the object's handle */
{
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object;
	char    object_name[64];
	int rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	snprintf(object_name, sizeof(object_name), "C_DestroyObject : Object %lu",
		(unsigned long) hObject);
	sc_debug( context, object_name );

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	rv = pool_find_and_delete(&session->slot->object_pool, hObject, (void**) &object);
	if (rv != CKR_OK)
		goto out;

	if (object->ops->destroy_object == NULL)
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	else
		rv = object->ops->destroy_object(session, object);

out:	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession,  /* the session's handle */
		      CK_OBJECT_HANDLE  hObject,   /* the object's handle */
		      CK_ULONG_PTR      pulSize)   /* receives size of object */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,   /* the session's handle */
			  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
			  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes, gets values */
			  CK_ULONG          ulCount)    /* attributes in template */
{
	static int precedence[] = {
		CKR_OK,
		CKR_BUFFER_TOO_SMALL,
		CKR_ATTRIBUTE_TYPE_INVALID,
		CKR_ATTRIBUTE_SENSITIVE,
		-1
	};
	char	object_name[64];
	int     j, rv;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object;
	int	res, res_type;
	unsigned int i;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	rv = pool_find(&session->slot->object_pool, hObject, (void**) &object);
	if (rv != CKR_OK)
		goto out;

	/* Debug printf */
	snprintf(object_name, sizeof(object_name), "Object %lu",
			(unsigned long) hObject);

	res_type = 0;
	for (i = 0; i < ulCount; i++) {
		res = object->ops->get_attribute(session,
					object, &pTemplate[i]);
		if (res != CKR_OK)
			pTemplate[i].ulValueLen = (CK_ULONG) -1;

		dump_template(object_name, &pTemplate[i], 1);

		/* the pkcs11 spec has complicated rules on
		 * what errors take precedence:
		 * 	CKR_ATTRIBUTE_SENSITIVE
		 * 	CKR_ATTRIBUTE_INVALID
		 * 	CKR_BUFFER_TOO_SMALL
		 * It does not exactly specify how other errors
		 * should be handled - we give them highest
		 * precedence
		 */
		for (j = 0; precedence[j] != -1; j++) {
			if (precedence[j] == res)
				break;
		}
		if (j > res_type) {
			res_type = j;
			rv = res;
		}
	}

out:	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,   /* the session's handle */
			  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
			  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes and values */
			  CK_ULONG          ulCount)    /* attributes in template */
{
	int rv;
	unsigned int i;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	dump_template("C_SetAttributeValue", pTemplate, ulCount);

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	rv = pool_find(&session->slot->object_pool, hObject, (void**) &object);
	if (rv != CKR_OK)
		goto out;

	if (object->ops->set_attribute == NULL)
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	else {
		for (i = 0; i < ulCount; i++) {
			rv = object->ops->set_attribute(session, object, &pTemplate[i]);
			if (rv != CKR_OK)
				break;
		}
	}

out:	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession,   /* the session's handle */
			CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
			CK_ULONG          ulCount)    /* attributes in search template */
{
	CK_BBOOL is_private = TRUE;
	CK_ATTRIBUTE private_attribute = { CKA_PRIVATE, &is_private, sizeof(is_private) };

	int rv, match, hide_private;
	unsigned int j;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object;
	struct sc_pkcs11_find_operation *operation;
	struct sc_pkcs11_pool_item *item;
	struct sc_pkcs11_slot *slot;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	sc_debug(context, "C_FindObjectsInit(slot = %d)\n", session->slot->id);
	dump_template("C_FindObjectsInit()", pTemplate, ulCount);

	rv = session_start_operation(session, SC_PKCS11_OPERATION_FIND,
                                     &find_mechanism,
				     (struct sc_pkcs11_operation**) &operation);
	if (rv != CKR_OK)
		goto out;

	operation->current_handle = 0;
	operation->num_handles = 0;
	slot = session->slot;

	/* Check whether we should hide private objects */
	hide_private = 0;
	if (slot->login_user != CKU_USER
	 && (slot->token_info.flags & CKF_LOGIN_REQUIRED))
		hide_private = 1;

	/* For each object in token do */
	for (item = slot->object_pool.head; item != NULL; item = item->next) {
		object = (struct sc_pkcs11_object*) item->item;

		/* User not logged in and private object? */
		if (hide_private) {
			if (object->ops->get_attribute(session, object, &private_attribute) != CKR_OK)
				continue;
			if (is_private) {
				sc_debug(context, "Object %d/%d: Private object and not logged in.\n",
					slot->id,
					item->handle);
				continue;
			}
		}

		/* Try to match every attribute */
		match = 1;
		for (j = 0; j < ulCount; j++) {
			rv = object->ops->cmp_attribute(session, object,
					&pTemplate[j]);
			if (rv == 0) {
				if (context->debug >= 4) {
					sc_debug(context, "Object %d/%d: Attribute 0x%x does NOT match.\n",
					      slot->id,
					      item->handle, pTemplate[j].type);
				}
				match = 0;
				break;
			}

			if (context->debug >= 4) {
				sc_debug(context, "Object %d/%d: Attribute 0x%x matches.\n",
				      slot->id,
				      item->handle, pTemplate[j].type);
			}
		}

		if (match) {
			sc_debug(context, "Object %d/%d matches\n",
			      slot->id, item->handle);
			/* Avoid buffer overflow --okir */
			if (operation->num_handles >= SC_PKCS11_FIND_MAX_HANDLES) {
				sc_debug(context, "Too many matching objects\n");
				break;
			}
			operation->handles[operation->num_handles++] = item->handle;
		}
	}
	rv = CKR_OK;

	sc_debug(context, "%d matching objects\n", operation->num_handles);

out:	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE    hSession,          /* the session's handle */
		    CK_OBJECT_HANDLE_PTR phObject,          /* receives object handle array */
		    CK_ULONG             ulMaxObjectCount,  /* max handles to be returned */
		    CK_ULONG_PTR         pulObjectCount)    /* actual number returned */
{
	int rv;
	CK_ULONG to_return;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_find_operation *operation;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_FIND,
				(sc_pkcs11_operation_t **) &operation);
	if (rv != CKR_OK)
		goto out;

	to_return = (CK_ULONG)operation->num_handles - operation->current_handle;
	if (to_return > ulMaxObjectCount)
		to_return = ulMaxObjectCount;

	*pulObjectCount = to_return;

	memcpy(phObject,
	       &operation->handles[operation->current_handle],
	       to_return * sizeof(CK_OBJECT_HANDLE));

	operation->current_handle += to_return;

out:	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession) /* the session's handle */
{
	int rv;
	struct sc_pkcs11_session *session;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_FIND, NULL);
	if (rv == CKR_OK)
		session_stop_operation(session, SC_PKCS11_OPERATION_FIND);

out:	sc_pkcs11_unlock();
	return rv;
}

/*
 * Below here all functions are wrappers to pass all object attribute and method
 * handling to appropriate object layer.
 */

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession,   /* the session's handle */
		   CK_MECHANISM_PTR  pMechanism) /* the digesting mechanism */
{
	int rv;
	struct sc_pkcs11_session *session;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv == CKR_OK)
		rv = sc_pkcs11_md_init(session, pMechanism);
	sc_debug(context, "C_DigestInit returns %d\n", rv);

	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession,     /* the session's handle */
	       CK_BYTE_PTR       pData,        /* data to be digested */
	       CK_ULONG          ulDataLen,    /* bytes of data to be digested */
	       CK_BYTE_PTR       pDigest,      /* receives the message digest */
	       CK_ULONG_PTR      pulDigestLen) /* receives byte length of digest */
{
	int rv;
	struct sc_pkcs11_session *session;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	rv = sc_pkcs11_md_update(session, pData, ulDataLen);
	if (rv == CKR_OK)
		rv = sc_pkcs11_md_final(session, pDigest, pulDigestLen);

out:	sc_debug(context, "C_Digest returns %d\n", rv);
	sc_pkcs11_unlock();

	return rv;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession,  /* the session's handle */
		     CK_BYTE_PTR       pPart,     /* data to be digested */
		     CK_ULONG          ulPartLen) /* bytes of data to be digested */
{
	int rv;
	struct sc_pkcs11_session *session;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv == CKR_OK)
		rv = sc_pkcs11_md_update(session, pPart, ulPartLen);

	sc_debug(context, "C_DigestUpdate returns %d\n", rv);
	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession,  /* the session's handle */
		  CK_OBJECT_HANDLE  hKey)      /* handle of secret key to digest */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession,     /* the session's handle */
		    CK_BYTE_PTR       pDigest,      /* receives the message digest */
		    CK_ULONG_PTR      pulDigestLen) /* receives byte count of digest */
{
	int rv;
	struct sc_pkcs11_session *session;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv == CKR_OK)
		rv = sc_pkcs11_md_final(session, pDigest, pulDigestLen);

	sc_debug(context, "C_DigestFinal returns %d\n", rv);
	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_SignInit(CK_SESSION_HANDLE hSession,    /* the session's handle */
		 CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
		 CK_OBJECT_HANDLE  hKey)        /* handle of the signature key */
{
	CK_BBOOL can_sign;
	CK_KEY_TYPE key_type;
	CK_ATTRIBUTE sign_attribute = { CKA_SIGN, &can_sign, sizeof(can_sign) };
	CK_ATTRIBUTE key_type_attr = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object;
	int rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	rv = pool_find(&session->slot->object_pool, hKey, (void**) &object);
	if (rv != CKR_OK)
		goto out;

	if (object->ops->sign == NULL_PTR) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	rv = object->ops->get_attribute(session, object, &sign_attribute);
	if (rv != CKR_OK || !can_sign) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}
	rv = object->ops->get_attribute(session, object, &key_type_attr);
	if (rv != CKR_OK) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	rv = sc_pkcs11_sign_init(session, pMechanism, object, key_type);

out:	sc_debug(context, "Sign initialization returns %d\n", rv);
	sc_pkcs11_unlock();

	return rv;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession,        /* the session's handle */
	     CK_BYTE_PTR       pData,           /* the data (digest) to be signed */
	     CK_ULONG          ulDataLen,       /* count of bytes to be signed */
	     CK_BYTE_PTR       pSignature,      /* receives the signature */
	     CK_ULONG_PTR      pulSignatureLen) /* receives byte count of signature */
{
	int rv;
	struct sc_pkcs11_session *session;
	CK_ULONG length;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	/* According to the pkcs11 specs, we must not do any calls that
	 * change our crypto state if the caller is just asking for the
	 * signature buffer size, or if the result would be
	 * CKR_BUFFER_TOO_SMALL. Thus we cannot do the sign_update call
	 * below. */
	if ((rv = sc_pkcs11_sign_size(session, &length)) != CKR_OK)
		goto out;

	if (pSignature == NULL || length > *pulSignatureLen) {
		*pulSignatureLen = length;
		rv = pSignature? CKR_BUFFER_TOO_SMALL : CKR_OK;
		goto out;
	}

	rv = sc_pkcs11_sign_update(session, pData, ulDataLen);
	if (rv == CKR_OK)
		rv = sc_pkcs11_sign_final(session, pSignature, pulSignatureLen);

out:	sc_debug(context, "Signing result was %d\n", rv);
	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession,  /* the session's handle */
		   CK_BYTE_PTR       pPart,     /* the data (digest) to be signed */
		   CK_ULONG          ulPartLen) /* count of bytes to be signed */
{
	struct sc_pkcs11_session *session;
	int rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv == CKR_OK)
		rv = sc_pkcs11_sign_update(session, pPart, ulPartLen);

	sc_debug(context, "C_SignUpdate returns %d\n", rv);
	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession,        /* the session's handle */
		  CK_BYTE_PTR       pSignature,      /* receives the signature */
		  CK_ULONG_PTR      pulSignatureLen) /* receives byte count of signature */
{
	struct sc_pkcs11_session *session;
	CK_ULONG length;
	int rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	/* According to the pkcs11 specs, we must not do any calls that
	 * change our crypto state if the caller is just asking for the
	 * signature buffer size, or if the result would be
	 * CKR_BUFFER_TOO_SMALL.
	 */
	if ((rv = sc_pkcs11_sign_size(session, &length)) != CKR_OK)
		goto out;

	if (pSignature == NULL || length > *pulSignatureLen) {
		*pulSignatureLen = length;
		rv = pSignature? CKR_BUFFER_TOO_SMALL : CKR_OK;
	} else {
		rv = sc_pkcs11_sign_final(session, pSignature, pulSignatureLen);
	}

out:	sc_debug(context, "C_SignFinal returns %d\n", rv);
	sc_pkcs11_unlock();

	return rv;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession,   /* the session's handle */
			CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
			CK_OBJECT_HANDLE  hKey)       /* handle of the signature key */
{
	CK_BBOOL can_sign;
	CK_KEY_TYPE key_type;
	CK_ATTRIBUTE sign_attribute = { CKA_SIGN, &can_sign, sizeof(can_sign) };
	CK_ATTRIBUTE key_type_attr = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object;
	int rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	rv = pool_find(&session->slot->object_pool, hKey, (void**) &object);
	if (rv != CKR_OK)
		goto out;

	if (object->ops->sign == NULL_PTR) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	rv = object->ops->get_attribute(session, object, &sign_attribute);
	if (rv != CKR_OK || !can_sign) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}
	rv = object->ops->get_attribute(session, object, &key_type_attr);
	if (rv != CKR_OK) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	/* XXX: need to tell the signature algorithm that we want
	 * to recover the signature */
	sc_debug(context, "SignRecover operation initialized\n");

	rv = sc_pkcs11_sign_init(session, pMechanism, object, key_type);

out:	sc_debug(context, "Sign initialization returns %d\n", rv);
	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession,        /* the session's handle */
		    CK_BYTE_PTR       pData,           /* the data (digest) to be signed */
		    CK_ULONG          ulDataLen,       /* count of bytes to be signed */
		    CK_BYTE_PTR       pSignature,      /* receives the signature */
		    CK_ULONG_PTR      pulSignatureLen) /* receives byte count of signature */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,    /* the session's handle */
		    CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
		    CK_OBJECT_HANDLE  hKey)        /* handle of encryption key */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,            /* the session's handle */
		CK_BYTE_PTR       pData,               /* the plaintext data */
		CK_ULONG          ulDataLen,           /* bytes of plaintext data */
		CK_BYTE_PTR       pEncryptedData,      /* receives encrypted data */
		CK_ULONG_PTR      pulEncryptedDataLen) /* receives encrypted byte count */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession,           /* the session's handle */
		      CK_BYTE_PTR       pPart,              /* the plaintext data */
		      CK_ULONG          ulPartLen,          /* bytes of plaintext data */
		      CK_BYTE_PTR       pEncryptedPart,     /* receives encrypted data */
		      CK_ULONG_PTR      pulEncryptedPartLen)/* receives encrypted byte count */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,                /* the session's handle */
		     CK_BYTE_PTR       pLastEncryptedPart,      /* receives encrypted last part */
		     CK_ULONG_PTR      pulLastEncryptedPartLen) /* receives byte count */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,    /* the session's handle */
		    CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
		    CK_OBJECT_HANDLE  hKey)        /* handle of the decryption key */
{
	CK_BBOOL can_decrypt;
	CK_KEY_TYPE key_type;
	CK_ATTRIBUTE decrypt_attribute = { CKA_DECRYPT, &can_decrypt, sizeof(can_decrypt) };
	CK_ATTRIBUTE key_type_attr = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object;
	int rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	rv = pool_find(&session->slot->object_pool, hKey, (void**) &object);
	if (rv != CKR_OK)
		goto out;

	if (object->ops->decrypt == NULL_PTR) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	rv = object->ops->get_attribute(session, object, &decrypt_attribute);
	if (rv != CKR_OK || !can_decrypt) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}
	rv = object->ops->get_attribute(session, object, &key_type_attr);
	if (rv != CKR_OK) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	rv = sc_pkcs11_decr_init(session, pMechanism, object, key_type);

out:	sc_debug(context, "Decrypt initialization returns %d\n", rv);
	sc_pkcs11_unlock();

	return rv;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,           /* the session's handle */
		CK_BYTE_PTR       pEncryptedData,     /* input encrypted data */
		CK_ULONG          ulEncryptedDataLen, /* count of bytes of input */
		CK_BYTE_PTR       pData,              /* receives decrypted output */
		CK_ULONG_PTR      pulDataLen)         /* receives decrypted byte count */
{
	int rv;
	struct sc_pkcs11_session *session;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	rv = sc_pkcs11_decr(session, pEncryptedData, ulEncryptedDataLen,
	                    pData, pulDataLen);

out:	sc_debug(context, "Decryption result was %d\n", rv);
	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession,            /* the session's handle */
		      CK_BYTE_PTR       pEncryptedPart,      /* input encrypted data */
		      CK_ULONG          ulEncryptedPartLen,  /* count of bytes of input */
		      CK_BYTE_PTR       pPart,               /* receives decrypted output */
		      CK_ULONG_PTR      pulPartLen)          /* receives decrypted byte count */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession,       /* the session's handle */
		     CK_BYTE_PTR       pLastPart,      /* receives decrypted output */
		     CK_ULONG_PTR      pulLastPartLen)  /* receives decrypted byte count */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,            /* the session's handle */
			    CK_BYTE_PTR       pPart,               /* the plaintext data */
			    CK_ULONG          ulPartLen,           /* bytes of plaintext data */
			    CK_BYTE_PTR       pEncryptedPart,      /* receives encrypted data */
			    CK_ULONG_PTR      pulEncryptedPartLen) /* receives encrypted byte count */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,            /* the session's handle */
			    CK_BYTE_PTR       pEncryptedPart,      /* input encrypted data */
			    CK_ULONG          ulEncryptedPartLen,  /* count of bytes of input */
			    CK_BYTE_PTR       pPart,               /* receives decrypted output */
			    CK_ULONG_PTR      pulPartLen)          /* receives decrypted byte count */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,            /* the session's handle */
			  CK_BYTE_PTR       pPart,               /* the plaintext data */
			  CK_ULONG          ulPartLen,           /* bytes of plaintext data */
			  CK_BYTE_PTR       pEncryptedPart,      /* receives encrypted data */
			  CK_ULONG_PTR      pulEncryptedPartLen) /* receives encrypted byte count */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,            /* the session's handle */
			    CK_BYTE_PTR       pEncryptedPart,      /* input encrypted data */
			    CK_ULONG          ulEncryptedPartLen,  /* count of byes of input */
			    CK_BYTE_PTR       pPart,               /* receives decrypted output */
			    CK_ULONG_PTR      pulPartLen)          /* receives decrypted byte count */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE    hSession,    /* the session's handle */
		    CK_MECHANISM_PTR     pMechanism,  /* the key generation mechanism */
		    CK_ATTRIBUTE_PTR     pTemplate,   /* template for the new key */
		    CK_ULONG             ulCount,     /* number of attributes in template */
		    CK_OBJECT_HANDLE_PTR phKey)       /* receives handle of new key */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE    hSession,                    /* the session's handle */
			CK_MECHANISM_PTR     pMechanism,                  /* the key gen. mech. */
			CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* pub. attr. template */
			CK_ULONG             ulPublicKeyAttributeCount,   /* # of pub. attrs. */
			CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* priv. attr. template */
			CK_ULONG             ulPrivateKeyAttributeCount,  /* # of priv. attrs. */
			CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub. key handle */
			CK_OBJECT_HANDLE_PTR phPrivateKey)                /* gets priv. key handle */
{
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_slot *slot;
	int rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;
	dump_template("C_CreateObject(), PrivKey attrs", pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	dump_template("C_CreateObject(), PubKey attrs", pPublicKeyTemplate, ulPublicKeyAttributeCount);

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	slot = session->slot;
	if (slot->card->framework->gen_keypair == NULL) {
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	} else {
		rv = slot->card->framework->gen_keypair(slot->card, slot,
			pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount,
			pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
			phPublicKey, phPrivateKey);
	}

out:	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession,        /* the session's handle */
		CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
		CK_OBJECT_HANDLE  hWrappingKey,    /* handle of the wrapping key */
		CK_OBJECT_HANDLE  hKey,            /* handle of the key to be wrapped */
		CK_BYTE_PTR       pWrappedKey,     /* receives the wrapped key */
		CK_ULONG_PTR      pulWrappedKeyLen)/* receives byte size of wrapped key */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE    hSession,          /* the session's handle */
		  CK_MECHANISM_PTR     pMechanism,        /* the unwrapping mechanism */
		  CK_OBJECT_HANDLE     hUnwrappingKey,    /* handle of the unwrapping key */
		  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
		  CK_ULONG             ulWrappedKeyLen,   /* bytes length of wrapped key */
		  CK_ATTRIBUTE_PTR     pTemplate,         /* template for the new key */
		  CK_ULONG             ulAttributeCount,  /* # of attributes in template */
		  CK_OBJECT_HANDLE_PTR phKey)             /* gets handle of recovered key */
{
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object, *result;
	int rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	rv = pool_find(&session->slot->object_pool, hUnwrappingKey,
				(void**) &object);
	if (rv != CKR_OK)
		goto out;

	if (object->ops->sign == NULL_PTR) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	rv = object->ops->unwrap_key(session, object, pMechanism,
				pWrappedKey, ulWrappedKeyLen,
				pTemplate, ulAttributeCount,
				(void **) &result);

	sc_debug(context, "Unwrapping result was %d\n", rv);

	if (rv == CKR_OK)
		rv = pool_insert(&session->slot->object_pool, result, phKey);

out:	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE    hSession,          /* the session's handle */
		  CK_MECHANISM_PTR     pMechanism,        /* the key derivation mechanism */
		  CK_OBJECT_HANDLE     hBaseKey,          /* handle of the base key */
		  CK_ATTRIBUTE_PTR     pTemplate,         /* template for the new key */
		  CK_ULONG             ulAttributeCount,  /* # of attributes in template */
		  CK_OBJECT_HANDLE_PTR phKey)             /* gets handle of derived key */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession,  /* the session's handle */
		   CK_BYTE_PTR       pSeed,     /* the seed material */
		   CK_ULONG          ulSeedLen) /* count of bytes of seed material */
{
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_slot    *slot;
	int rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv == CKR_OK) {
		slot = session->slot;
		if (slot->card->framework->get_random == NULL)
			rv = CKR_RANDOM_NO_RNG;
		else if (slot->card->framework->seed_random == NULL)
			rv = CKR_RANDOM_SEED_NOT_SUPPORTED;
		else
			rv = slot->card->framework->seed_random(slot->card, pSeed, ulSeedLen);
	}

	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession,    /* the session's handle */
		       CK_BYTE_PTR       RandomData,  /* receives the random data */
		       CK_ULONG          ulRandomLen) /* number of bytes to be generated */
{
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_slot    *slot;
	int rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv == CKR_OK) {
		slot = session->slot;
		if (slot->card->framework->get_random == NULL)
			rv = CKR_RANDOM_NO_RNG;
		else
			rv = slot->card->framework->get_random(slot->card, RandomData, ulRandomLen);
	}

	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession) /* the session's handle */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession) /* the session's handle */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,    /* the session's handle */
		   CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
		   CK_OBJECT_HANDLE  hKey)        /* handle of the verification key */
{
#ifndef ENABLE_OPENSSL
	return CKR_FUNCTION_NOT_SUPPORTED;
#else
#if 0
	CK_BBOOL can_verify;
	CK_ATTRIBUTE verify_attribute = { CKA_VERIFY, &can_verify, sizeof(can_verify) };
#endif
	CK_KEY_TYPE key_type;
	CK_ATTRIBUTE key_type_attr = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object;
	int rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	rv = pool_find(&session->slot->object_pool, hKey, (void**) &object);
	if (rv != CKR_OK)
		goto out;

#if 0
	rv = object->ops->get_attribute(session, object, &verify_attribute);
	if (rv != CKR_OK || !can_verify) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}
#endif
	rv = object->ops->get_attribute(session, object, &key_type_attr);
	if (rv != CKR_OK) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	rv = sc_pkcs11_verif_init(session, pMechanism, object, key_type);

out:	sc_debug(context, "Verify initialization returns %d\n", rv);
	sc_pkcs11_unlock();

	return rv;
#endif
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession,       /* the session's handle */
	       CK_BYTE_PTR       pData,          /* plaintext data (digest) to compare */
	       CK_ULONG          ulDataLen,      /* length of data (digest) in bytes */
	       CK_BYTE_PTR       pSignature,     /* the signature to be verified */
	       CK_ULONG          ulSignatureLen) /* count of bytes of signature */
{
#ifndef ENABLE_OPENSSL
	return CKR_FUNCTION_NOT_SUPPORTED;
#else
	int rv;
	struct sc_pkcs11_session *session;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	rv = sc_pkcs11_verif_update(session, pData, ulDataLen);
	if (rv == CKR_OK)
		rv = sc_pkcs11_verif_final(session, pSignature, ulSignatureLen);

out:	sc_debug(context, "Verify result was %d\n", rv);
	sc_pkcs11_unlock();
	return rv;
#endif
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession,  /* the session's handle */
		     CK_BYTE_PTR       pPart,     /* plaintext data (digest) to compare */
		     CK_ULONG          ulPartLen) /* length of data (digest) in bytes */
{
#ifndef ENABLE_OPENSSL
	return CKR_FUNCTION_NOT_SUPPORTED;
#else
	struct sc_pkcs11_session *session;
	int rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv == CKR_OK)
		rv = sc_pkcs11_verif_update(session, pPart, ulPartLen);

	sc_debug(context, "C_VerifyUpdate returns %d\n", rv);
	sc_pkcs11_unlock();
	return rv;
#endif
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession,       /* the session's handle */
		    CK_BYTE_PTR       pSignature,     /* the signature to be verified */
		    CK_ULONG          ulSignatureLen) /* count of bytes of signature */
{
#ifndef ENABLE_OPENSSL
	return CKR_FUNCTION_NOT_SUPPORTED;
#else
	struct sc_pkcs11_session *session;
	int rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = pool_find(&session_pool, hSession, (void**) &session);
	if (rv != CKR_OK)
		goto out;

	rv = sc_pkcs11_verif_final(session, pSignature, ulSignatureLen);

out:	sc_debug(context, "C_VerifyFinal returns %d\n", rv);
	sc_pkcs11_unlock();

	return rv;
#endif
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,    /* the session's handle */
			  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
			  CK_OBJECT_HANDLE  hKey)        /* handle of the verification key */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession,        /* the session's handle */
		      CK_BYTE_PTR       pSignature,      /* the signature to be verified */
		      CK_ULONG          ulSignatureLen,  /* count of bytes of signature */
		      CK_BYTE_PTR       pData,           /* receives decrypted data (digest) */
		      CK_ULONG_PTR      pulDataLen)      /* receives byte count of data */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/*
 * Helper function to compare attributes on any sort of object
 */
int
sc_pkcs11_any_cmp_attribute(struct sc_pkcs11_session *session,
		void *ptr, CK_ATTRIBUTE_PTR attr)
{
	struct sc_pkcs11_object *object;
	u8		temp1[1024];
	u8		*temp2 = NULL; /* dynamic allocation for large attributes */
	CK_ATTRIBUTE	temp_attr;
	int		rv, res;

	object = (struct sc_pkcs11_object *) ptr;
	temp_attr.type = attr->type;
	temp_attr.pValue = NULL;
	temp_attr.ulValueLen = 0;

	/* Get the length of the attribute */
	rv = object->ops->get_attribute(session, object, &temp_attr);
	if (rv != CKR_OK || temp_attr.ulValueLen != attr->ulValueLen)
		return 0;

	if (temp_attr.ulValueLen <= sizeof(temp1))
		temp_attr.pValue = temp1;
	else {
		temp2 = (u8 *) malloc(temp_attr.ulValueLen);
		if (temp2 == NULL)
			return 0;
		temp_attr.pValue = temp2;
	}

	/* Get the attribute */
	rv = object->ops->get_attribute(session, object, &temp_attr);
	if (rv != CKR_OK) {
		res = 0;
		goto done;
	}

#ifdef DEBUG
	{
		char	foo[64];

		snprintf(foo, sizeof(foo), "Object %p (slot %d)",
				object, session->slot->id);
		dump_template(foo, &temp_attr, 1);
	}
#endif
	res = temp_attr.ulValueLen == attr->ulValueLen
	    && !memcmp(temp_attr.pValue, attr->pValue, attr->ulValueLen);

done:
	if (temp2 != NULL)
		free(temp2);

	return res;
}
