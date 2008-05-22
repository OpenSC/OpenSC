/*
 * Secret key handling for PKCS#11
 *
 * This module deals only with secret keys that have been unwrapped
 * by the card. At the moment, we do not support key unwrapping
 * where the key remains on the token.
 *
 * Copyright (C) 2002  Olaf Kirch <okir@lst.de>
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

struct pkcs11_secret_key {
	struct sc_pkcs11_object object;

	char *		label;
	CK_KEY_TYPE	type;
	CK_BYTE_PTR	value;
	CK_ULONG	value_len;
};

extern struct sc_pkcs11_object_ops pkcs11_secret_key_ops;

#define set_attr(var, attr)			\
	if (attr->ulValueLen != sizeof(var))	\
		return CKR_ATTRIBUTE_VALUE_INVALID; \
	memcpy(&var, attr->pValue, attr->ulValueLen);
#define check_attr(attr, size)			\
	if (attr->pValue == NULL_PTR) {		\
		attr->ulValueLen = size;	\
		return CKR_OK;			\
	}					\
	if (attr->ulValueLen < size) {		\
		attr->ulValueLen = size;	\
		return CKR_BUFFER_TOO_SMALL;	\
	}					\
	attr->ulValueLen = size;
#define get_attr(attr, type, value)		\
	check_attr(attr, sizeof(type));		\
	*(type *) (attr->pValue) = value;

CK_RV
sc_pkcs11_create_secret_key(struct sc_pkcs11_session *session,
		const u8 *value, size_t value_len,
		CK_ATTRIBUTE_PTR _template,
		CK_ULONG attribute_count,
		struct sc_pkcs11_object **out)
{
	struct pkcs11_secret_key *key;
	CK_ATTRIBUTE_PTR attr;
	int		n, rv;

	key = (struct pkcs11_secret_key *) calloc(1, sizeof(*key));
	if (!key)
		return CKR_HOST_MEMORY;
	key->value = (CK_BYTE *) malloc(value_len);
	if (!key->value) {
		pkcs11_secret_key_ops.release(key);
		return CKR_HOST_MEMORY; /* XXX correct? */
	}
	memcpy(key->value, value, value_len);
	key->value_len = value_len;
	key->object.ops = &pkcs11_secret_key_ops;

	/* Make sure the key type is given in the template */
	for (n = attribute_count, attr = _template; n--; attr++) {
		if (attr->type == CKA_KEY_TYPE) {
			set_attr(key->type, attr);
			break;
		}
	}
	if (n < 0) {
		pkcs11_secret_key_ops.release(key);
		return CKR_TEMPLATE_INCOMPLETE;
	}

	/* Set all the other attributes */
	for (n = attribute_count, attr = _template; n--; attr++) {
		rv = key->object.ops->set_attribute(session, key, attr);
		if (rv != CKR_OK) {
			pkcs11_secret_key_ops.release(key);
			return rv;
		}
	}

	*out = (struct sc_pkcs11_object *) key;
	return CKR_OK;
}

static void
sc_pkcs11_secret_key_release(void *object)
{
	struct pkcs11_secret_key *key;

	key = (struct pkcs11_secret_key *) object;
	if (key) {
		if (key->value)
			free(key->value);
		if (key->label)
			free(key->label);
		free(key);
	}
}

static CK_RV
sc_pkcs11_secret_key_set_attribute(struct sc_pkcs11_session *session,
				void *object, CK_ATTRIBUTE_PTR attr)
{
	struct pkcs11_secret_key *key;
	CK_OBJECT_CLASS	ck_class;
	CK_KEY_TYPE ck_key_type;
	CK_BBOOL ck_bbool;

	key = (struct pkcs11_secret_key *) object;
	switch (attr->type) {
	case CKA_CLASS:
		set_attr(ck_class, attr);
		if (ck_class != CKO_SECRET_KEY)
			return CKR_ATTRIBUTE_VALUE_INVALID;
		break;
	case CKA_KEY_TYPE:
		set_attr(ck_key_type, attr);
		if (ck_key_type != key->type)
			return CKR_ATTRIBUTE_VALUE_INVALID;
		break;
	case CKA_LABEL:
		if (key->label)
			free(key->label);
		key->label = strdup((const char *) attr->pValue);
		break;
	case CKA_TOKEN:
		set_attr(ck_bbool, attr);
		if (!ck_bbool)
			return CKR_ATTRIBUTE_VALUE_INVALID;
		break;
	case CKA_VALUE:
		if (key->value)
			free(key->value);
		key->value = (CK_BYTE *) malloc(attr->ulValueLen);
		if (key->value == NULL)
			return CKR_HOST_MEMORY;
		key->value_len = attr->ulValueLen;
		memcpy(key->value, attr->pValue, key->value_len);
		break;
	case CKA_ENCRYPT:
	case CKA_DECRYPT:
	case CKA_SIGN:
	case CKA_VERIFY:
	case CKA_WRAP:
	case CKA_UNWRAP:
	case CKA_EXTRACTABLE:
	case CKA_ALWAYS_SENSITIVE:
	case CKA_NEVER_EXTRACTABLE:
		/* We ignore these for now, just making sure the argument
		 * has the right size */
		set_attr(ck_bbool, attr);
		break;
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	return CKR_OK;
}

static CK_RV
sc_pkcs11_secret_key_get_attribute(struct sc_pkcs11_session *session,
				void *object, CK_ATTRIBUTE_PTR attr)
{
	struct pkcs11_secret_key *key;

	key = (struct pkcs11_secret_key *) object;
	switch (attr->type) {
	case CKA_CLASS:
		get_attr(attr, CK_OBJECT_CLASS, CKO_SECRET_KEY);
		break;
	case CKA_KEY_TYPE:
		get_attr(attr, CK_KEY_TYPE, key->type);
	case CKA_VALUE:
		check_attr(attr, key->value_len);
		memcpy(attr->pValue, key->value, key->value_len);
		break;
	case CKA_VALUE_LEN:
		get_attr(attr, CK_ULONG, key->value_len);
		break;
	case CKA_SENSITIVE:
	case CKA_SIGN:
	case CKA_VERIFY:
	case CKA_WRAP:
	case CKA_UNWRAP:
	case CKA_NEVER_EXTRACTABLE:
		get_attr(attr, CK_BBOOL, 0);
		break;
	case CKA_ENCRYPT:
	case CKA_DECRYPT:
	case CKA_EXTRACTABLE:
	case CKA_ALWAYS_SENSITIVE:
		get_attr(attr, CK_BBOOL, 1);
		break;
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
	return CKR_OK;
}

struct sc_pkcs11_object_ops pkcs11_secret_key_ops = {
	sc_pkcs11_secret_key_release,
	sc_pkcs11_secret_key_set_attribute,
	sc_pkcs11_secret_key_get_attribute,
	sc_pkcs11_any_cmp_attribute,
	NULL,	/* destroy_object */
	NULL,	/* get_size */
	NULL,	/* sign */
	NULL,	/* unwrap_key */
	NULL	/* decrypt */
};
