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

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "sc-pkcs11.h"

static void sc_find_release(sc_pkcs11_operation_t *operation);

/* Pseudo mechanism for the Find operation */
static sc_pkcs11_mechanism_type_t find_mechanism = {
	0,		/* mech */
	{0,0,0},	/* mech_info */
	0,		/* key_type */
	sizeof(struct sc_pkcs11_find_operation),	/* obj_size */
	sc_find_release,				/* release */
	NULL,		/* md_init */
	NULL,		/* md_update */
	NULL,		/* md_final */
	NULL,		/* sign_init */
	NULL,		/* sign_update */
	NULL,		/* sign_final */
	NULL,		/* sign_size */
	NULL,		/* verif_init */
	NULL,		/* verif_update */
	NULL,		/* verif_final */
	NULL,		/* decrypt_init */
	NULL,		/* decrypt */
	NULL,		/* derive */
	NULL,		/* wrap */
	NULL,		/* unwrap */
	NULL,		/* mech_data */
	NULL,		/* free_mech_data */
};

static void
sc_find_release(sc_pkcs11_operation_t *operation)
{
	struct sc_pkcs11_find_operation *fop = (struct sc_pkcs11_find_operation *)operation;

	if (fop->handles) {
		free(fop->handles);
		fop->handles = NULL;
	}
}


static CK_RV
get_object_from_session(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		struct sc_pkcs11_session **session, struct sc_pkcs11_object **object)
{
	struct sc_pkcs11_session *sess;
	CK_RV rv;

	rv = get_session(hSession, &sess);
	if (rv != CKR_OK)
		return rv;

	*object = list_seek(&sess->slot->objects, &hObject);
	if (!*object)
		return CKR_OBJECT_HANDLE_INVALID;
	*session = sess;
	return CKR_OK;
}

/* C_CreateObject can be called from C_DeriveKey
 * which is holding the sc_pkcs11_lock
 * So dont get the lock again. */
static
CK_RV sc_create_object_int(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_ATTRIBUTE_PTR pTemplate,		/* the object's template */
		CK_ULONG ulCount,			/* attributes in template */
		CK_OBJECT_HANDLE_PTR phObject,		/* receives new object's handle. */
		int use_lock)
{
	CK_RV rv = CKR_OK;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_card *card;
	CK_BBOOL is_token = FALSE;

	LOG_FUNC_CALLED(context);
	if (pTemplate == NULL_PTR || ulCount == 0)
		return CKR_ARGUMENTS_BAD;

	if (use_lock) {
	    rv = sc_pkcs11_lock();
	    if (rv != CKR_OK)
		return rv;
	}

	dump_template(SC_LOG_DEBUG_NORMAL, "C_CreateObject()", pTemplate, ulCount);

	session = list_seek(&sessions, &hSession);
	if (!session) {
		rv = CKR_SESSION_HANDLE_INVALID;
		goto out;
	}

	rv = attr_find(pTemplate, ulCount, CKA_TOKEN, &is_token, NULL);
	if (rv != CKR_TEMPLATE_INCOMPLETE && rv != CKR_OK) {
		goto out;
	}

	if (is_token == TRUE) {
		if (session->slot->token_info.flags & CKF_WRITE_PROTECTED) {
			rv = CKR_TOKEN_WRITE_PROTECTED;
			goto out;
		}
		if (!(session->flags & CKF_RW_SESSION)) {
			rv = CKR_SESSION_READ_ONLY;
			goto out;
		}
	}

	card = session->slot->p11card;
	if (card->framework->create_object == NULL)
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	else
		rv = card->framework->create_object(session->slot, pTemplate, ulCount, phObject);

out:
	if (use_lock)
		sc_pkcs11_unlock();

	return rv;
}


CK_RV
C_CreateObject(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_ATTRIBUTE_PTR pTemplate,	/* the object's template */
		CK_ULONG ulCount,		/* attributes in template */
		CK_OBJECT_HANDLE_PTR phObject)
{
	return sc_create_object_int(hSession, pTemplate, ulCount, phObject, 1);
}


CK_RV
C_CopyObject(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_OBJECT_HANDLE hObject,	/* the object's handle */
		CK_ATTRIBUTE_PTR pTemplate,	/* template for new object */
		CK_ULONG ulCount,		/* attributes in template */
		CK_OBJECT_HANDLE_PTR phNewObject)	/* receives handle of copy */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV
C_DestroyObject(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_OBJECT_HANDLE hObject)	/* the object's handle */
{
	CK_RV rv;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object;
	CK_BBOOL is_token = FALSE;
	CK_ATTRIBUTE token_attribute = {CKA_TOKEN, &is_token, sizeof(is_token)};

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	sc_log(context, "C_DestroyObject(hSession=0x%lx, hObject=0x%lx)", hSession, hObject);
	rv = get_object_from_session(hSession, hObject, &session, &object);
	if (rv != CKR_OK)
		goto out;

	object->ops->get_attribute(session, object, &token_attribute);
	if (is_token == TRUE) {
		if (session->slot->token_info.flags & CKF_WRITE_PROTECTED) {
			rv = CKR_TOKEN_WRITE_PROTECTED;
			goto out;
		}
		if (!(session->flags & CKF_RW_SESSION)) {
			rv = CKR_SESSION_READ_ONLY;
			goto out;
		}
	}

	if (object->ops->destroy_object == NULL)
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	else
		rv = object->ops->destroy_object(session, object);

out:
	sc_pkcs11_unlock();
	return rv;
}


CK_RV
C_GetObjectSize(CK_SESSION_HANDLE hSession,	/* the session's handle */
		      CK_OBJECT_HANDLE hObject,	/* the object's handle */
		      CK_ULONG_PTR pulSize)	/* receives size of object */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV
C_GetAttributeValue(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_OBJECT_HANDLE hObject,	/* the object's handle */
		CK_ATTRIBUTE_PTR pTemplate,	/* specifies attributes, gets values */
		CK_ULONG ulCount)		/* attributes in template */
{
	static CK_RV precedence[] = {
		CKR_OK,
		CKR_BUFFER_TOO_SMALL,
		CKR_ATTRIBUTE_TYPE_INVALID,
		CKR_ATTRIBUTE_SENSITIVE,
		-1
	};
	char object_name[64];
	CK_RV j;
	CK_RV rv;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object;
	CK_RV res;
	CK_RV res_type;
	unsigned int i;

	if (pTemplate == NULL_PTR || ulCount == 0)
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_object_from_session(hSession, hObject, &session, &object);
	if (rv != CKR_OK)
		goto out;

	/* Debug printf */
	snprintf(object_name, sizeof(object_name), "Object %lu", (unsigned long)hObject);

	res_type = 0;
	for (i = 0; i < ulCount; i++) {
		res = object->ops->get_attribute(session, object, &pTemplate[i]);
		if (res != CKR_OK)
			pTemplate[i].ulValueLen = (CK_ULONG) - 1;

		dump_template(SC_LOG_DEBUG_NORMAL, object_name, &pTemplate[i], 1);

		/* the pkcs11 spec has complicated rules on
		 * what errors take precedence:
		 *      CKR_ATTRIBUTE_SENSITIVE
		 *      CKR_ATTRIBUTE_INVALID
		 *      CKR_BUFFER_TOO_SMALL
		 * It does not exactly specify how other errors
		 * should be handled - we give them highest
		 * precedence
		 */
		for (j = 0; precedence[j] != (CK_RV) -1; j++) {
			if (precedence[j] == res)
				break;
		}
		if (j > res_type) {
			res_type = j;
			rv = res;
		}
	}

out:	sc_log(context, "C_GetAttributeValue(hSession=0x%lx, hObject=0x%lx) = %s",
			hSession, hObject, lookup_enum ( RV_T, rv ));
	sc_pkcs11_unlock();
	return rv;
}


CK_RV
C_SetAttributeValue(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_OBJECT_HANDLE hObject,	/* the object's handle */
		CK_ATTRIBUTE_PTR pTemplate,	/* specifies attributes and values */
		CK_ULONG ulCount)		/* attributes in template */
{
	CK_RV rv;
	unsigned int i;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object;

	if (pTemplate == NULL_PTR || ulCount == 0)
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	dump_template(SC_LOG_DEBUG_NORMAL, "C_SetAttributeValue", pTemplate, ulCount);

	rv = get_object_from_session(hSession, hObject, &session, &object);
	if (rv != CKR_OK)
		goto out;

	if (!(session->flags & CKF_RW_SESSION)) {
		rv = CKR_SESSION_READ_ONLY;
		goto out;
	}

	if (object->ops->set_attribute == NULL)
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	else {
		for (i = 0; i < ulCount; i++) {
			rv = object->ops->set_attribute(session, object, &pTemplate[i]);
			if (rv != CKR_OK)
				break;
		}
	}

out:
	sc_pkcs11_unlock();
	return rv;
}


CK_RV
C_FindObjectsInit(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_ATTRIBUTE_PTR pTemplate,	/* attribute values to match */
		CK_ULONG ulCount)		/* attributes in search template */
{
	CK_RV rv;
	CK_BBOOL is_private = TRUE;
	CK_ATTRIBUTE private_attribute = { CKA_PRIVATE, &is_private, sizeof(is_private) };
	int match, hide_private;
	unsigned int i, j;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object;
	struct sc_pkcs11_find_operation *operation;
	struct sc_pkcs11_slot *slot;

	if (pTemplate == NULL_PTR && ulCount > 0)
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv != CKR_OK)
		goto out;

	sc_log(context, "C_FindObjectsInit(slot = %lu)\n", session->slot->id);
	dump_template(SC_LOG_DEBUG_NORMAL, "C_FindObjectsInit()", pTemplate, ulCount);

	rv = session_start_operation(session, SC_PKCS11_OPERATION_FIND,
				     &find_mechanism, (struct sc_pkcs11_operation **)&operation);
	if (rv != CKR_OK)
		goto out;

	operation->current_handle = 0;
	operation->num_handles = 0;
	operation->allocated_handles = 0;
	operation->handles = NULL;
	slot = session->slot;

	/* Check whether we should hide private objects */
	hide_private = 0;
	if (slot->login_user != CKU_USER && (slot->token_info.flags & CKF_LOGIN_REQUIRED))
		hide_private = 1;

	/* For each object in token do */
	for (i=0; i<list_size(&slot->objects); i++) {
		object = (struct sc_pkcs11_object *)list_get_at(&slot->objects, i);
		sc_log(context, "Object with handle 0x%lx", object->handle);

		/* User not logged in and private object? */
		if (hide_private) {
			if (object->ops->get_attribute(session, object, &private_attribute) != CKR_OK)
			        continue;
			if (is_private) {
				sc_log(context,
				       "Object %lu/%lu: Private object and not logged in.",
				       slot->id, object->handle);
				continue;
			}
		}

		/* Try to match every attribute */
		match = 1;
		for (j = 0; j < ulCount; j++) {
			rv = object->ops->cmp_attribute(session, object, &pTemplate[j]);
			if (rv == 0) {
				sc_log(context,
				       "Object %lu/%lu: Attribute 0x%lx does NOT match.",
				       slot->id, object->handle, pTemplate[j].type);
				match = 0;
				break;
			}

			if (context->debug >= 4) {
				sc_log(context,
				       "Object %lu/%lu: Attribute 0x%lx matches.",
				       slot->id, object->handle, pTemplate[j].type);
			}
		}

		if (match) {
			sc_log(context, "Object %lu/%lu matches\n", slot->id,
			       object->handle);
			/* Realloc handles - remove restriction on only 32 matching objects -dee */
			if (operation->num_handles >= operation->allocated_handles) {
				operation->allocated_handles += SC_PKCS11_FIND_INC_HANDLES;
				sc_log(context, "realloc for %d handles", operation->allocated_handles);
				operation->handles = realloc(operation->handles,
					sizeof(CK_OBJECT_HANDLE) * operation->allocated_handles);
				if (operation->handles == NULL) {
					rv = CKR_HOST_MEMORY;
					goto out;
				}
			}
			operation->handles[operation->num_handles++] = object->handle;
		}
	}
	rv = CKR_OK;

	sc_log(context, "%d matching objects\n", operation->num_handles);

out:
	sc_pkcs11_unlock();
	return rv;
}


CK_RV
C_FindObjects(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_OBJECT_HANDLE_PTR phObject,	/* receives object handle array */
		CK_ULONG ulMaxObjectCount,	/* max handles to be returned */
		CK_ULONG_PTR pulObjectCount)	/* actual number returned */
{
	CK_RV rv;
	CK_ULONG to_return;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_find_operation *operation;

	if (phObject == NULL_PTR || ulMaxObjectCount == 0 || pulObjectCount == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv != CKR_OK)
		goto out;

	rv = session_get_operation(session, SC_PKCS11_OPERATION_FIND, (sc_pkcs11_operation_t **) & operation);
	if (rv != CKR_OK)
		goto out;

	to_return = (CK_ULONG) operation->num_handles - operation->current_handle;
	if (to_return > ulMaxObjectCount)
		to_return = ulMaxObjectCount;

	*pulObjectCount = to_return;

	memcpy(phObject, &operation->handles[operation->current_handle], to_return * sizeof(CK_OBJECT_HANDLE));

	operation->current_handle += to_return;

out:	sc_pkcs11_unlock();
	return rv;
}


CK_RV
C_FindObjectsFinal(CK_SESSION_HANDLE hSession)	/* the session's handle */
{
	CK_RV rv;
	struct sc_pkcs11_session *session;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
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
CK_RV
C_DigestInit(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_MECHANISM_PTR pMechanism)	/* the digesting mechanism */
{
	CK_RV rv;
	struct sc_pkcs11_session *session;

	if (pMechanism == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	sc_log(context, "C_DigestInit(hSession=0x%lx)", hSession);
	rv = get_session(hSession, &session);
	if (rv == CKR_OK)
		rv = sc_pkcs11_md_init(session, pMechanism);

	sc_log(context, "C_DigestInit() = %s", lookup_enum ( RV_T, rv ));
	sc_pkcs11_unlock();
	return rv;
}


CK_RV
C_Digest(CK_SESSION_HANDLE hSession,		/* the session's handle */
		CK_BYTE_PTR pData,		/* data to be digested */
		CK_ULONG ulDataLen,		/* bytes of data to be digested */
		CK_BYTE_PTR pDigest,		/* receives the message digest */
		CK_ULONG_PTR pulDigestLen)	/* receives byte length of digest */
{
	CK_RV rv;
	struct sc_pkcs11_session *session;
	CK_ULONG  ulBuflen = 0;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	sc_log(context, "C_Digest(hSession=0x%lx)", hSession);
	rv = get_session(hSession, &session);
	if (rv != CKR_OK)
		goto out;

	/* if pDigest == NULL, buffer size request */
	if (pDigest) {
	    /* As per PKCS#11 2.20 we need to check if buffer too small before update */
	    rv = sc_pkcs11_md_final(session, NULL, &ulBuflen);
	    if (rv != CKR_OK)
		goto out;

	    if (ulBuflen > *pulDigestLen) {
	        *pulDigestLen = ulBuflen;
		rv = CKR_BUFFER_TOO_SMALL;
		goto out;
	    }

	    rv = sc_pkcs11_md_update(session, pData, ulDataLen);
	}
	if (rv == CKR_OK)
		rv = sc_pkcs11_md_final(session, pDigest, pulDigestLen);

out:
	sc_log(context, "C_Digest() = %s", lookup_enum ( RV_T, rv ));
	sc_pkcs11_unlock();
	return rv;
}


CK_RV
C_DigestUpdate(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_BYTE_PTR pPart,		/* data to be digested */
		CK_ULONG ulPartLen)		/* bytes of data to be digested */
{
	CK_RV rv;
	struct sc_pkcs11_session *session;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK)
		rv = sc_pkcs11_md_update(session, pPart, ulPartLen);

	sc_log(context, "C_DigestUpdate() == %s", lookup_enum ( RV_T, rv ));
	sc_pkcs11_unlock();
	return rv;
}


CK_RV
C_DigestKey(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_OBJECT_HANDLE hKey)	/* handle of secret key to digest */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV
C_DigestFinal(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_BYTE_PTR pDigest,		/* receives the message digest */
		CK_ULONG_PTR pulDigestLen)	/* receives byte count of digest */
{
	CK_RV rv;
	struct sc_pkcs11_session *session;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK)
		rv = sc_pkcs11_md_final(session, pDigest, pulDigestLen);

	sc_log(context, "C_DigestFinal() = %s", lookup_enum ( RV_T, rv ));
	sc_pkcs11_unlock();
	return rv;
}


CK_RV
C_SignInit(CK_SESSION_HANDLE hSession,		/* the session's handle */
		CK_MECHANISM_PTR pMechanism,	/* the signature mechanism */
		CK_OBJECT_HANDLE hKey)		/* handle of the signature key */
{
	CK_BBOOL can_sign;
	CK_KEY_TYPE key_type;
	CK_ATTRIBUTE sign_attribute = { CKA_SIGN, &can_sign, sizeof(can_sign) };
	CK_ATTRIBUTE key_type_attr = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object;
	CK_RV rv;

	if (pMechanism == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_object_from_session(hSession, hKey, &session, &object);
	if (rv != CKR_OK) {
		if (rv == CKR_OBJECT_HANDLE_INVALID)
			rv = CKR_KEY_HANDLE_INVALID;
		goto out;
	}

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

out:
	sc_log(context, "C_SignInit() = %s", lookup_enum ( RV_T, rv ));
	sc_pkcs11_unlock();
	return rv;
}


CK_RV
C_Sign(CK_SESSION_HANDLE hSession,		/* the session's handle */
		CK_BYTE_PTR pData,		/* the data (digest) to be signed */
		CK_ULONG ulDataLen,		/* count of bytes to be signed */
		CK_BYTE_PTR pSignature,		/* receives the signature */
		CK_ULONG_PTR pulSignatureLen)	/* receives byte count of signature */
{
	CK_RV rv;
	struct sc_pkcs11_session *session;
	CK_ULONG length;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
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
		rv = pSignature ? CKR_BUFFER_TOO_SMALL : CKR_OK;
		goto out;
	}

	rv = sc_pkcs11_sign_update(session, pData, ulDataLen);
	if (rv == CKR_OK) {
		rv = restore_login_state(session->slot);
		if (rv == CKR_OK)
			rv = sc_pkcs11_sign_final(session, pSignature, pulSignatureLen);
		rv = reset_login_state(session->slot, rv);
	}

out:
	sc_log(context, "C_Sign() = %s", lookup_enum ( RV_T, rv ));
	sc_pkcs11_unlock();
	return rv;
}


CK_RV
C_SignUpdate(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_BYTE_PTR pPart,		/* the data (digest) to be signed */
		CK_ULONG ulPartLen)		/* count of bytes to be signed */
{
	CK_RV rv;
	struct sc_pkcs11_session *session;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK)
		rv = sc_pkcs11_sign_update(session, pPart, ulPartLen);

	sc_log(context, "C_SignUpdate() = %s", lookup_enum ( RV_T, rv ));
	sc_pkcs11_unlock();
	return rv;
}


CK_RV
C_SignFinal(CK_SESSION_HANDLE hSession,		/* the session's handle */
		CK_BYTE_PTR pSignature,		/* receives the signature */
		CK_ULONG_PTR pulSignatureLen)	/* receives byte count of signature */
{
	struct sc_pkcs11_session *session;
	CK_ULONG length;
	CK_RV rv;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
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
		rv = pSignature ? CKR_BUFFER_TOO_SMALL : CKR_OK;
	} else {
		rv = restore_login_state(session->slot);
		if (rv == CKR_OK)
			rv = sc_pkcs11_sign_final(session, pSignature, pulSignatureLen);
		rv = reset_login_state(session->slot, rv);
	}

out:
	sc_log(context, "C_SignFinal() = %s", lookup_enum ( RV_T, rv ));
	sc_pkcs11_unlock();
	return rv;
}


CK_RV
C_SignRecoverInit(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_MECHANISM_PTR pMechanism,	/* the signature mechanism */
		CK_OBJECT_HANDLE hKey)		/* handle of the signature key */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV
C_SignRecover(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_BYTE_PTR pData,		/* the data (digest) to be signed */
		CK_ULONG ulDataLen,		/* count of bytes to be signed */
		CK_BYTE_PTR pSignature,		/* receives the signature */
		CK_ULONG_PTR pulSignatureLen)	/* receives byte count of signature */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV
C_EncryptInit(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_MECHANISM_PTR pMechanism,	/* the encryption mechanism */
		CK_OBJECT_HANDLE hKey)		/* handle of encryption key */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_BYTE_PTR pData,	/* the plaintext data */
		CK_ULONG ulDataLen,	/* bytes of plaintext data */
		CK_BYTE_PTR pEncryptedData,	/* receives encrypted data */
		CK_ULONG_PTR pulEncryptedDataLen)
{				/* receives encrypted byte count */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession,	/* the session's handle */
		      CK_BYTE_PTR pPart,	/* the plaintext data */
		      CK_ULONG ulPartLen,	/* bytes of plaintext data */
		      CK_BYTE_PTR pEncryptedPart,	/* receives encrypted data */
		      CK_ULONG_PTR pulEncryptedPartLen)
{				/* receives encrypted byte count */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,	/* the session's handle */
		     CK_BYTE_PTR pLastEncryptedPart,	/* receives encrypted last part */
		     CK_ULONG_PTR pulLastEncryptedPartLen)
{				/* receives byte count */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,	/* the session's handle */
		    CK_MECHANISM_PTR pMechanism,	/* the decryption mechanism */
		    CK_OBJECT_HANDLE hKey)
{				/* handle of the decryption key */
	CK_BBOOL can_decrypt, can_unwrap;
	CK_KEY_TYPE key_type;
	CK_ATTRIBUTE decrypt_attribute = { CKA_DECRYPT,	&can_decrypt,	sizeof(can_decrypt) };
	CK_ATTRIBUTE key_type_attr = { CKA_KEY_TYPE,	&key_type,	sizeof(key_type) };
	CK_ATTRIBUTE unwrap_attribute = { CKA_UNWRAP,	&can_unwrap,	sizeof(can_unwrap) };
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object;
	CK_RV rv;

	if (pMechanism == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_object_from_session(hSession, hKey, &session, &object);
	if (rv != CKR_OK) {
		if (rv == CKR_OBJECT_HANDLE_INVALID)
			rv = CKR_KEY_HANDLE_INVALID;
		goto out;
	}

	if (object->ops->decrypt == NULL_PTR) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	rv = object->ops->get_attribute(session, object, &decrypt_attribute);
	if (rv != CKR_OK || !can_decrypt) {
		/* Also accept UNWRAP - apps call Decrypt when they mean Unwrap */
		rv = object->ops->get_attribute(session, object, &unwrap_attribute);
		if (rv != CKR_OK || !can_unwrap) {
			rv = CKR_KEY_TYPE_INCONSISTENT;
			goto out;
		}
	}
	rv = object->ops->get_attribute(session, object, &key_type_attr);
	if (rv != CKR_OK) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	rv = sc_pkcs11_decr_init(session, pMechanism, object, key_type);

out:
	sc_log(context, "C_DecryptInit() = %s", lookup_enum ( RV_T, rv ));
	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_BYTE_PTR pEncryptedData,	/* input encrypted data */
		CK_ULONG ulEncryptedDataLen,	/* count of bytes of input */
		CK_BYTE_PTR pData,	/* receives decrypted output */
		CK_ULONG_PTR pulDataLen)
{				/* receives decrypted byte count */
	CK_RV rv;
	struct sc_pkcs11_session *session;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK) {
		rv = restore_login_state(session->slot);
		if (rv == CKR_OK) {
			rv = sc_pkcs11_decr(session, pEncryptedData,
					ulEncryptedDataLen, pData, pulDataLen);
		}
		rv = reset_login_state(session->slot, rv);
	}

	sc_log(context, "C_Decrypt() = %s", lookup_enum ( RV_T, rv ));
	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession,	/* the session's handle */
		      CK_BYTE_PTR pEncryptedPart,	/* input encrypted data */
		      CK_ULONG ulEncryptedPartLen,	/* count of bytes of input */
		      CK_BYTE_PTR pPart,	/* receives decrypted output */
		      CK_ULONG_PTR pulPartLen)
{				/* receives decrypted byte count */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession,	/* the session's handle */
		     CK_BYTE_PTR pLastPart,	/* receives decrypted output */
		     CK_ULONG_PTR pulLastPartLen)
{				/* receives decrypted byte count */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,	/* the session's handle */
			    CK_BYTE_PTR pPart,	/* the plaintext data */
			    CK_ULONG ulPartLen,	/* bytes of plaintext data */
			    CK_BYTE_PTR pEncryptedPart,	/* receives encrypted data */
			    CK_ULONG_PTR pulEncryptedPartLen)
{				/* receives encrypted byte count */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,	/* the session's handle */
			    CK_BYTE_PTR pEncryptedPart,	/* input encrypted data */
			    CK_ULONG ulEncryptedPartLen,	/* count of bytes of input */
			    CK_BYTE_PTR pPart,	/* receives decrypted output */
			    CK_ULONG_PTR pulPartLen)
{				/* receives decrypted byte count */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,	/* the session's handle */
			  CK_BYTE_PTR pPart,	/* the plaintext data */
			  CK_ULONG ulPartLen,	/* bytes of plaintext data */
			  CK_BYTE_PTR pEncryptedPart,	/* receives encrypted data */
			  CK_ULONG_PTR pulEncryptedPartLen)
{				/* receives encrypted byte count */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,	/* the session's handle */
			    CK_BYTE_PTR pEncryptedPart,	/* input encrypted data */
			    CK_ULONG ulEncryptedPartLen,	/* count of byes of input */
			    CK_BYTE_PTR pPart,	/* receives decrypted output */
			    CK_ULONG_PTR pulPartLen)
{				/* receives decrypted byte count */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,	/* the session's handle */
		    CK_MECHANISM_PTR pMechanism,	/* the key generation mechanism */
		    CK_ATTRIBUTE_PTR pTemplate,	/* template for the new key */
		    CK_ULONG ulCount,	/* number of attributes in template */
		    CK_OBJECT_HANDLE_PTR phKey)
{				/* receives handle of new key */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,	/* the session's handle */
			CK_MECHANISM_PTR pMechanism,	/* the key gen. mech. */
			CK_ATTRIBUTE_PTR pPublicKeyTemplate,	/* pub. attr. template */
			CK_ULONG ulPublicKeyAttributeCount,	/* # of pub. attrs. */
			CK_ATTRIBUTE_PTR pPrivateKeyTemplate,	/* priv. attr. template */
			CK_ULONG ulPrivateKeyAttributeCount,	/* # of priv. attrs. */
			CK_OBJECT_HANDLE_PTR phPublicKey,	/* gets pub. key handle */
			CK_OBJECT_HANDLE_PTR phPrivateKey)
{				/* gets priv. key handle */
	CK_RV rv;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_slot *slot;

	if (pMechanism == NULL_PTR
			|| (pPublicKeyTemplate == NULL_PTR && ulPublicKeyAttributeCount > 0)
			|| (pPrivateKeyTemplate == NULL_PTR && ulPrivateKeyAttributeCount > 0))
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	dump_template(SC_LOG_DEBUG_NORMAL, "C_GenerateKeyPair(), PrivKey attrs", pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	dump_template(SC_LOG_DEBUG_NORMAL, "C_GenerateKeyPair(), PubKey attrs", pPublicKeyTemplate, ulPublicKeyAttributeCount);

	rv = get_session(hSession, &session);
	if (rv != CKR_OK)
		goto out;

	if (!(session->flags & CKF_RW_SESSION)) {
		rv = CKR_SESSION_READ_ONLY;
		goto out;
	}

	slot = session->slot;
	if (slot == NULL || slot->p11card == NULL || slot->p11card->framework == NULL
			|| slot->p11card->framework->gen_keypair == NULL)
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	else {
		rv = restore_login_state(slot);
		if (rv == CKR_OK)
			rv = slot->p11card->framework->gen_keypair(slot, pMechanism,
					pPublicKeyTemplate, ulPublicKeyAttributeCount,
					pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
					phPublicKey, phPrivateKey);
		rv = reset_login_state(session->slot, rv);
	}

out:
	sc_pkcs11_unlock();
	return rv;
}


CK_RV C_WrapKey(CK_SESSION_HANDLE hSession,	/* the session's handle */
		CK_MECHANISM_PTR pMechanism,	/* the wrapping mechanism */
		CK_OBJECT_HANDLE hWrappingKey,	/* handle of the wrapping key */
		CK_OBJECT_HANDLE hKey,	/* handle of the key to be wrapped */
		CK_BYTE_PTR pWrappedKey,	/* receives the wrapped key */
		CK_ULONG_PTR pulWrappedKeyLen)
{				/* receives byte size of wrapped key */
	CK_RV rv;
	CK_BBOOL can_wrap,
			 can_be_wrapped;
	CK_KEY_TYPE key_type;
	CK_ATTRIBUTE wrap_attribute = { CKA_WRAP, &can_wrap, sizeof(can_wrap) };
	CK_ATTRIBUTE extractable_attribute = { CKA_EXTRACTABLE, &can_be_wrapped, sizeof(can_be_wrapped) };
	CK_ATTRIBUTE key_type_attr = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *wrapping_object;
	struct sc_pkcs11_object *key_object;

	if (pMechanism == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	/* Check if the wrapping key is OK to do wrapping */
	rv = get_object_from_session(hSession, hWrappingKey, &session, &wrapping_object);
	if (rv != CKR_OK) {
		if (rv == CKR_OBJECT_HANDLE_INVALID)
			rv = CKR_KEY_HANDLE_INVALID;
		goto out;
	}
	if (wrapping_object->ops->wrap_key == NULL_PTR) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	rv = wrapping_object->ops->get_attribute(session, wrapping_object, &wrap_attribute);
	if (rv != CKR_OK || !can_wrap) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}
	rv = wrapping_object->ops->get_attribute(session, wrapping_object, &key_type_attr);
	if (rv != CKR_OK) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	/* Check if the key to be wrapped exists and is extractable*/
	rv = get_object_from_session(hSession, hKey, &session, &key_object);
	if (rv != CKR_OK) {
		if (rv == CKR_OBJECT_HANDLE_INVALID)
			rv = CKR_KEY_HANDLE_INVALID;
		goto out;
	}

	rv = key_object->ops->get_attribute(session, key_object, &extractable_attribute);
	if (rv != CKR_OK || !can_be_wrapped) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	rv = restore_login_state(session->slot);
	if (rv == CKR_OK)
		rv = sc_pkcs11_wrap(session, pMechanism, wrapping_object, key_type,
				key_object, pWrappedKey, pulWrappedKeyLen);

	rv = reset_login_state(session->slot, rv);

out:
	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession,	/* the session's handle */
		  CK_MECHANISM_PTR pMechanism,	/* the unwrapping mechanism */
		  CK_OBJECT_HANDLE hUnwrappingKey,	/* handle of the unwrapping key */
		  CK_BYTE_PTR pWrappedKey,	/* the wrapped key */
		  CK_ULONG ulWrappedKeyLen,	/* bytes length of wrapped key */
		  CK_ATTRIBUTE_PTR pTemplate,	/* template for the new key */
		  CK_ULONG ulAttributeCount,	/* # of attributes in template */
		  CK_OBJECT_HANDLE_PTR phKey)
{				/* gets handle of recovered key */
	CK_RV rv;
	CK_BBOOL can_unwrap;
	CK_KEY_TYPE key_type;
	CK_ATTRIBUTE unwrap_attribute = { CKA_UNWRAP, &can_unwrap, sizeof(can_unwrap) };
	CK_ATTRIBUTE key_type_attr = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object;
	struct sc_pkcs11_object *key_object;

	if (pMechanism == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_object_from_session(hSession, hUnwrappingKey, &session, &object);
	if (rv != CKR_OK) {
		if (rv == CKR_OBJECT_HANDLE_INVALID)
			rv = CKR_KEY_HANDLE_INVALID;
		goto out;
	}
	if (object->ops->unwrap_key == NULL_PTR) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	rv = object->ops->get_attribute(session, object, &unwrap_attribute);
	if (rv != CKR_OK || !can_unwrap) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}
	rv = object->ops->get_attribute(session, object, &key_type_attr);
	if (rv != CKR_OK) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	/* Create the target object in memory */
	rv = sc_create_object_int(hSession, pTemplate, ulAttributeCount, phKey, 0);

	if (rv != CKR_OK)
	    goto out;

	rv = get_object_from_session(hSession, *phKey, &session, &key_object);
	if (rv != CKR_OK) {
		if (rv == CKR_OBJECT_HANDLE_INVALID)
			rv = CKR_KEY_HANDLE_INVALID;
		goto out;
	}

	rv = restore_login_state(session->slot);
	if (rv == CKR_OK)
		rv = sc_pkcs11_unwrap(session, pMechanism, object, key_type,
				pWrappedKey, ulWrappedKeyLen, key_object);
	/* TODO if (rv != CK_OK) need to destroy the object */
	rv = reset_login_state(session->slot, rv);

out:
	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession,	/* the session's handle */
		  CK_MECHANISM_PTR pMechanism,	/* the key derivation mechanism */
		  CK_OBJECT_HANDLE hBaseKey,	/* handle of the base key */
		  CK_ATTRIBUTE_PTR pTemplate,	/* template for the new key */
		  CK_ULONG ulAttributeCount,	/* # of attributes in template */
		  CK_OBJECT_HANDLE_PTR phKey)	/* gets handle of derived key */
{
/* TODO: -DEE ECDH with Cofactor  on PIV is an example */
/* TODO: need to do a lot of checking, will only support ECDH for now.*/
	CK_RV rv;
	CK_BBOOL can_derive;
	CK_KEY_TYPE key_type;
	CK_ATTRIBUTE derive_attribute = { CKA_DERIVE, &can_derive, sizeof(can_derive) };
	CK_ATTRIBUTE key_type_attr = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object;
	struct sc_pkcs11_object *key_object;

	if (pMechanism == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_object_from_session(hSession, hBaseKey, &session, &object);
	if (rv != CKR_OK) {
		if (rv == CKR_OBJECT_HANDLE_INVALID)
			rv = CKR_KEY_HANDLE_INVALID;
		goto out;
	}

	if (object->ops->derive == NULL_PTR) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	rv = object->ops->get_attribute(session, object, &derive_attribute);
	if (rv != CKR_OK || !can_derive) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}
	rv = object->ops->get_attribute(session, object, &key_type_attr);
	if (rv != CKR_OK) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}
	/* TODO DEE Should also check SENSITIVE, ALWAYS_SENSITIVE, EXTRACTABLE,
	   NEVER_EXTRACTABLE of the BaseKey against the template for the newkey.
	*/

	switch(key_type) {
	    case CKK_EC:

		rv = sc_create_object_int(hSession, pTemplate, ulAttributeCount, phKey, 0);
		if (rv != CKR_OK)
		    goto out;

		rv = get_object_from_session(hSession, *phKey, &session, &key_object);
		if (rv != CKR_OK) {
			if (rv == CKR_OBJECT_HANDLE_INVALID)
				rv = CKR_KEY_HANDLE_INVALID;
			goto out;
		}

		rv = restore_login_state(session->slot);
		if (rv == CKR_OK)
			rv = sc_pkcs11_deri(session, pMechanism, object, key_type,
					hSession, *phKey, key_object);
		/* TODO if (rv != CK_OK) need to destroy the object */
		rv = reset_login_state(session->slot, rv);

		break;
	    default:
		rv = CKR_KEY_TYPE_INCONSISTENT;
	}

out:
	sc_pkcs11_unlock();
	return rv;
}

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession,	/* the session's handle */
		   CK_BYTE_PTR pSeed,	/* the seed material */
		   CK_ULONG ulSeedLen)
{				/* count of bytes of seed material */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession,	/* the session's handle */
		       CK_BYTE_PTR RandomData,	/* receives the random data */
		       CK_ULONG ulRandomLen)
{				/* number of bytes to be generated */
	CK_RV rv;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_slot *slot;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK) {
		slot = session->slot;
		if (slot == NULL || slot->p11card == NULL || slot->p11card->framework == NULL
				|| slot->p11card->framework->get_random == NULL)
			rv = CKR_RANDOM_NO_RNG;
		else
			rv = slot->p11card->framework->get_random(slot, RandomData, ulRandomLen);
	}

	sc_pkcs11_unlock();
	sc_log(context, "C_GenerateRandom() = %s", lookup_enum ( RV_T, rv ));
	return rv;
}

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{				/* the session's handle */
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{				/* the session's handle */
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,	/* the session's handle */
		   CK_MECHANISM_PTR pMechanism,	/* the verification mechanism */
		   CK_OBJECT_HANDLE hKey)
{				/* handle of the verification key */
#ifndef ENABLE_OPENSSL
	return CKR_FUNCTION_NOT_SUPPORTED;
#else
	CK_KEY_TYPE key_type;
	CK_ATTRIBUTE key_type_attr = { CKA_KEY_TYPE, &key_type, sizeof(key_type) };
	CK_RV rv;
	struct sc_pkcs11_session *session;
	struct sc_pkcs11_object *object;

	if (pMechanism == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;


	rv = get_object_from_session(hSession, hKey, &session, &object);
	if (rv != CKR_OK) {
		if (rv == CKR_OBJECT_HANDLE_INVALID)
			rv = CKR_KEY_HANDLE_INVALID;
		goto out;
	}
	rv = object->ops->get_attribute(session, object, &key_type_attr);
	if (rv != CKR_OK) {
		rv = CKR_KEY_TYPE_INCONSISTENT;
		goto out;
	}

	rv = sc_pkcs11_verif_init(session, pMechanism, object, key_type);

out:
	sc_log(context, "C_VerifyInit() = %s", lookup_enum ( RV_T, rv ));
	sc_pkcs11_unlock();
	return rv;
#endif
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession,	/* the session's handle */
	       CK_BYTE_PTR pData,	/* plaintext data (digest) to compare */
	       CK_ULONG ulDataLen,	/* length of data (digest) in bytes */
	       CK_BYTE_PTR pSignature,	/* the signature to be verified */
	       CK_ULONG ulSignatureLen)
{				/* count of bytes of signature */
#ifndef ENABLE_OPENSSL
	return CKR_FUNCTION_NOT_SUPPORTED;
#else
	CK_RV rv;
	struct sc_pkcs11_session *session;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv != CKR_OK)
		goto out;

	rv = sc_pkcs11_verif_update(session, pData, ulDataLen);
	if (rv == CKR_OK) {
		rv = restore_login_state(session->slot);
		if (rv == CKR_OK)
			rv = sc_pkcs11_verif_final(session, pSignature, ulSignatureLen);
		rv = reset_login_state(session->slot, rv);
	}

out:
	sc_log(context, "C_Verify() = %s", lookup_enum ( RV_T, rv ));
	sc_pkcs11_unlock();
	return rv;
#endif
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession,	/* the session's handle */
		     CK_BYTE_PTR pPart,	/* plaintext data (digest) to compare */
		     CK_ULONG ulPartLen)
{				/* length of data (digest) in bytes */
#ifndef ENABLE_OPENSSL
	return CKR_FUNCTION_NOT_SUPPORTED;
#else
	CK_RV rv;
	struct sc_pkcs11_session *session;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK)
		rv = sc_pkcs11_verif_update(session, pPart, ulPartLen);

	sc_log(context, "C_VerifyUpdate() = %s", lookup_enum ( RV_T, rv ));
	sc_pkcs11_unlock();
	return rv;
#endif
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession,	/* the session's handle */
		    CK_BYTE_PTR pSignature,	/* the signature to be verified */
		    CK_ULONG ulSignatureLen)
{				/* count of bytes of signature */
#ifndef ENABLE_OPENSSL
	return CKR_FUNCTION_NOT_SUPPORTED;
#else
	CK_RV rv;
	struct sc_pkcs11_session *session;

	rv = sc_pkcs11_lock();
	if (rv != CKR_OK)
		return rv;

	rv = get_session(hSession, &session);
	if (rv == CKR_OK) {
		rv = restore_login_state(session->slot);
		if (rv == CKR_OK)
			rv = sc_pkcs11_verif_final(session, pSignature, ulSignatureLen);
		rv = reset_login_state(session->slot, rv);
	}

	sc_log(context, "C_VerifyFinal() = %s", lookup_enum ( RV_T, rv ));
	sc_pkcs11_unlock();
	return rv;
#endif
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,	/* the session's handle */
			  CK_MECHANISM_PTR pMechanism,	/* the verification mechanism */
			  CK_OBJECT_HANDLE hKey)
{				/* handle of the verification key */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession,	/* the session's handle */
		      CK_BYTE_PTR pSignature,	/* the signature to be verified */
		      CK_ULONG ulSignatureLen,	/* count of bytes of signature */
		      CK_BYTE_PTR pData,	/* receives decrypted data (digest) */
		      CK_ULONG_PTR pulDataLen)
{				/* receives byte count of data */
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/*
 * Helper function to compare attributes on any sort of object
 */
CK_RV sc_pkcs11_any_cmp_attribute(struct sc_pkcs11_session *session, void *ptr, CK_ATTRIBUTE_PTR attr)
{
	CK_RV rv;
	struct sc_pkcs11_object *object;
	u8 temp1[1024];
	u8 *temp2 = NULL;	/* dynamic allocation for large attributes */
	CK_ATTRIBUTE temp_attr;

	object = (struct sc_pkcs11_object *)ptr;
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
		temp2 = calloc(1, temp_attr.ulValueLen);
		if (temp2 == NULL)
			return 0;
		temp_attr.pValue = temp2;
	}

	/* Get the attribute */
	rv = object->ops->get_attribute(session, object, &temp_attr);
	if (rv != CKR_OK) {
		rv = 0;
		goto done;
	}
#ifdef DEBUG
	{
		char foo[64];

		snprintf(foo, sizeof(foo), "Object %p (slot 0x%lx)", object, session->slot->id);
		dump_template(SC_LOG_DEBUG_NORMAL, foo, &temp_attr, 1);
	}
#endif
	rv = temp_attr.ulValueLen == attr->ulValueLen
	    && !memcmp(temp_attr.pValue, attr->pValue, attr->ulValueLen);

      done:
	if (temp2 != NULL)
		free(temp2);

	return rv;
}
