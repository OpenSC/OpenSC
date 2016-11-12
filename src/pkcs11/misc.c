/*
 * misc.c: Miscellaneous PKCS#11 library helper functions
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

#define DUMP_TEMPLATE_MAX	32

struct sc_to_cryptoki_error_conversion  {
	const char *context;
	int sc_error;
	CK_RV ck_error;
};

static struct sc_to_cryptoki_error_conversion sc_to_cryptoki_error_map[]  = {
	{ "C_GenerateKeyPair",	SC_ERROR_INVALID_PIN_LENGTH,	CKR_GENERAL_ERROR },
	{ "C_Sign",		SC_ERROR_NOT_ALLOWED,		CKR_FUNCTION_FAILED},
	{ "C_Decrypt",		SC_ERROR_NOT_ALLOWED,		CKR_FUNCTION_FAILED},
	{NULL, 0, 0}
};


void strcpy_bp(u8 * dst, const char *src, size_t dstsize)
{
	size_t c;

	if (!dst || !src || !dstsize)
		return;

	memset((char *)dst, ' ', dstsize);

	c = strlen(src) > dstsize ? dstsize : strlen(src);

	memcpy((char *)dst, src, c);
}


static CK_RV sc_to_cryptoki_error_common(int rc)
{
	sc_log(context, "libopensc return value: %d (%s)\n", rc, sc_strerror(rc));
	switch (rc) {
	case SC_SUCCESS:
		return CKR_OK;
	case SC_ERROR_NOT_SUPPORTED:
		return CKR_FUNCTION_NOT_SUPPORTED;
	case SC_ERROR_OUT_OF_MEMORY:
		return CKR_HOST_MEMORY;
	case SC_ERROR_PIN_CODE_INCORRECT:
		return CKR_PIN_INCORRECT;
	case SC_ERROR_AUTH_METHOD_BLOCKED:
		return CKR_PIN_LOCKED;
	case SC_ERROR_BUFFER_TOO_SMALL:
		return CKR_BUFFER_TOO_SMALL;
	case SC_ERROR_CARD_NOT_PRESENT:
		return CKR_TOKEN_NOT_PRESENT;
	case SC_ERROR_INVALID_CARD:
	case SC_ERROR_WRONG_CARD:
	case SC_ERROR_NO_CARD_SUPPORT:
		return CKR_TOKEN_NOT_RECOGNIZED;
	case SC_ERROR_WRONG_LENGTH:
		return CKR_DATA_LEN_RANGE;
	case SC_ERROR_INVALID_PIN_LENGTH:
		return CKR_PIN_LEN_RANGE;
	case SC_ERROR_KEYPAD_CANCELLED:
	case SC_ERROR_KEYPAD_TIMEOUT:
		return CKR_FUNCTION_CANCELED;
	case SC_ERROR_CARD_REMOVED:
		return CKR_DEVICE_REMOVED;
	case SC_ERROR_SECURITY_STATUS_NOT_SATISFIED:
		return CKR_USER_NOT_LOGGED_IN;
	case SC_ERROR_KEYPAD_PIN_MISMATCH:
		return CKR_PIN_INVALID;
	case SC_ERROR_INVALID_ARGUMENTS:
		return CKR_ARGUMENTS_BAD;
	case SC_ERROR_INVALID_DATA:
	case SC_ERROR_INCORRECT_PARAMETERS:
		return CKR_DATA_INVALID;
	case SC_ERROR_CARD_UNRESPONSIVE:
	case SC_ERROR_READER_LOCKED:
		return CKR_DEVICE_ERROR;
	case SC_ERROR_READER_DETACHED:
		return CKR_TOKEN_NOT_PRESENT;	/* Maybe CKR_DEVICE_REMOVED ? */
	case SC_ERROR_NOT_ENOUGH_MEMORY:
		return CKR_DEVICE_MEMORY;
	case SC_ERROR_MEMORY_FAILURE:	/* EEPROM has failed */
		return CKR_DEVICE_ERROR;
	}
	return CKR_GENERAL_ERROR;
}


CK_RV sc_to_cryptoki_error(int rc, const char *ctx)
{
	if (ctx)   {
		int ii;

		for (ii = 0; sc_to_cryptoki_error_map[ii].context; ii++) {
			if (sc_to_cryptoki_error_map[ii].sc_error != rc)
				continue;
			if (strcmp(sc_to_cryptoki_error_map[ii].context, ctx))
				continue;
			return sc_to_cryptoki_error_map[ii].ck_error;
		}
	}
	return sc_to_cryptoki_error_common(rc);
}


struct sc_pkcs11_login {
	CK_USER_TYPE userType;
	CK_CHAR_PTR pPin;
	CK_ULONG ulPinLen;
};

CK_RV restore_login_state(struct sc_pkcs11_slot *slot)
{
	CK_RV r = CKR_OK;

	if (sc_pkcs11_conf.atomic && slot) {
		if (list_iterator_start(&slot->logins)) {
			struct sc_pkcs11_login *login = list_iterator_next(&slot->logins);
			while (login) {
				r = slot->p11card->framework->login(slot, login->userType,
						login->pPin, login->ulPinLen);
				if (r != CKR_OK)
					break;
				login = list_iterator_next(&slot->logins);
			}
			list_iterator_stop(&slot->logins);
		}
	}

	return r;
}

CK_RV reset_login_state(struct sc_pkcs11_slot *slot, CK_RV rv)
{
	if (slot) {
		if (sc_pkcs11_conf.atomic
				&& slot->p11card && slot->p11card->framework) {
			slot->p11card->framework->logout(slot);
		}

		if (rv == CKR_USER_NOT_LOGGED_IN) {
			slot->login_user = -1;
			pop_all_login_states(slot);
		}
	}

	return rv;
}

CK_RV push_login_state(struct sc_pkcs11_slot *slot,
		CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV r = CKR_HOST_MEMORY;
	struct sc_pkcs11_login *login = NULL;

	if (!sc_pkcs11_conf.atomic || !slot) {
		return CKR_OK;
	}

	login = (struct sc_pkcs11_login *) calloc(1, sizeof *login);
	if (login == NULL) {
		goto err;
	}

	login->pPin = sc_mem_alloc_secure(context, (sizeof *pPin)*ulPinLen);
	if (login->pPin == NULL) {
		goto err;
	}
	memcpy(login->pPin, pPin, (sizeof *pPin)*ulPinLen);
	login->ulPinLen = ulPinLen;
	login->userType = userType;

	if (0 > list_append(&slot->logins, login)) {
		goto err;
	}

	login = NULL;
	r = CKR_OK;

err:
	if (login) {
		if (login->pPin) {
			sc_mem_clear(login->pPin, login->ulPinLen);
			free(login->pPin);
		}
		free(login);
	}

	return r;
}

void pop_login_state(struct sc_pkcs11_slot *slot)
{
	if (slot) {
		unsigned int size = list_size(&slot->logins);
		if (size > 0) {
			struct sc_pkcs11_login *login = list_get_at(&slot->logins, size-1);
			if (login) {
				sc_mem_clear(login->pPin, login->ulPinLen);
				free(login->pPin);
				free(login);
			}
			if (0 > list_delete_at(&slot->logins, size-1))
				sc_log(context, "Error deleting login state");
		}
	}
}

void pop_all_login_states(struct sc_pkcs11_slot *slot)
{
	if (sc_pkcs11_conf.atomic && slot) {
		struct sc_pkcs11_login *login = list_fetch(&slot->logins);
		while (login) {
			sc_mem_clear(login->pPin, login->ulPinLen);
			free(login->pPin);
			free(login);
			login = list_fetch(&slot->logins);
		}
	}
}


/* Session manipulation */
CK_RV session_start_operation(struct sc_pkcs11_session * session,
			      int type, sc_pkcs11_mechanism_type_t * mech, struct sc_pkcs11_operation ** operation)
{
	sc_pkcs11_operation_t *op;

	if (context == NULL)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	LOG_FUNC_CALLED(context);
	sc_log(context, "Session 0x%lx, type %d", session->handle, type);
	if (type < 0 || type >= SC_PKCS11_OPERATION_MAX)
		return CKR_ARGUMENTS_BAD;

	if (session->operation[type] != NULL)
		return CKR_OPERATION_ACTIVE;

	if (!(op = sc_pkcs11_new_operation(session, mech)))
		return CKR_HOST_MEMORY;

	session->operation[type] = op;
	if (operation)
		*operation = op;

	return CKR_OK;
}

CK_RV session_get_operation(struct sc_pkcs11_session * session, int type, sc_pkcs11_operation_t ** operation)
{
	sc_pkcs11_operation_t *op;

	LOG_FUNC_CALLED(context);

	if (type < 0 || type >= SC_PKCS11_OPERATION_MAX)
		return CKR_ARGUMENTS_BAD;

	if (!(op = session->operation[type]))
		return CKR_OPERATION_NOT_INITIALIZED;

	if (operation)
		*operation = op;

	return CKR_OK;
}

CK_RV session_stop_operation(struct sc_pkcs11_session * session, int type)
{
	if (type < 0 || type >= SC_PKCS11_OPERATION_MAX)
		return CKR_ARGUMENTS_BAD;

	if (session->operation[type] == NULL)
		return CKR_OPERATION_NOT_INITIALIZED;

	sc_pkcs11_release_operation(&session->operation[type]);
	return CKR_OK;
}

CK_RV attr_extract(CK_ATTRIBUTE_PTR pAttr, void *ptr, size_t * sizep)
{
	unsigned int size;

	if (sizep) {
		size = *sizep;
		if (size < pAttr->ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
		*sizep = pAttr->ulValueLen;
	} else {
		switch (pAttr->type) {
		case CKA_CLASS:
			size = sizeof(CK_OBJECT_CLASS);
			break;
		case CKA_KEY_TYPE:
			size = sizeof(CK_KEY_TYPE);
			break;
		case CKA_PRIVATE:
		case CKA_TOKEN:
			size = sizeof(CK_BBOOL);
			break;
		case CKA_CERTIFICATE_TYPE:
			size = sizeof(CK_CERTIFICATE_TYPE);
			break;
		case CKA_VALUE_LEN:
		case CKA_MODULUS_BITS:
			size = sizeof(CK_ULONG);
			break;
		case CKA_OBJECT_ID:
			size = sizeof(struct sc_object_id);
			break;
		default:
			return CKR_FUNCTION_FAILED;
		}
		if (size != pAttr->ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}
	memcpy(ptr, pAttr->pValue, pAttr->ulValueLen);
	return CKR_OK;
}

CK_RV attr_find(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ULONG type, void *ptr, size_t * sizep)
{
	unsigned int n;

	for (n = 0; n < ulCount; n++, pTemplate++) {
		if (pTemplate->type == type)
			break;
	}

	if (n >= ulCount)
		return CKR_TEMPLATE_INCOMPLETE;
	return attr_extract(pTemplate, ptr, sizep);
}

CK_RV attr_find2(CK_ATTRIBUTE_PTR pTemp1, CK_ULONG ulCount1,
		 CK_ATTRIBUTE_PTR pTemp2, CK_ULONG ulCount2, CK_ULONG type, void *ptr, size_t * sizep)
{
	CK_RV rv;

	rv = attr_find(pTemp1, ulCount1, type, ptr, sizep);
	if (rv != CKR_OK)
		rv = attr_find(pTemp2, ulCount2, type, ptr, sizep);

	return rv;
}

CK_RV attr_find_and_allocate_ptr(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ULONG type, void **out, size_t *out_len)
{
	void *ptr;
	size_t len;
	CK_RV rv;

	if (!out || !out_len)
		return CKR_ARGUMENTS_BAD;
	len = *out_len;

	rv = attr_find_ptr(pTemplate, ulCount, type, &ptr, &len);
	if (rv != CKR_OK)
		return rv;

	*out = calloc(1, len);
	if (*out == NULL)
		return CKR_HOST_MEMORY;

	memcpy(*out, ptr, len);
	*out_len = len;

	return CKR_OK;
}

CK_RV attr_find_ptr(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ULONG type, void **ptr, size_t * sizep)
{
	unsigned int n;

	for (n = 0; n < ulCount; n++, pTemplate++) {
		if (pTemplate->type == type)
			break;
	}

	if (n >= ulCount)
		return CKR_TEMPLATE_INCOMPLETE;

	if (sizep)
		*sizep = pTemplate->ulValueLen;
	*ptr = pTemplate->pValue;
	return CKR_OK;
}

CK_RV attr_find_var(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ULONG type, void *ptr, size_t * sizep)
{
	unsigned int n;

	for (n = 0; n < ulCount; n++, pTemplate++) {
		if (pTemplate->type == type)
			break;
	}

	if (n >= ulCount)
		return CKR_TEMPLATE_INCOMPLETE;

	return attr_extract(pTemplate, ptr, sizep);
}

void load_pkcs11_parameters(struct sc_pkcs11_config *conf, sc_context_t * ctx)
{
	scconf_block *conf_block = NULL;
	char *unblock_style = NULL;
	char *create_slots_for_pins = NULL, *op, *tmp;

	/* Set defaults */
	conf->max_virtual_slots = 16;
	if (strcmp(ctx->app_name, "onepin-opensc-pkcs11") == 0) {
		conf->slots_per_card = 1;
	} else {
		conf->slots_per_card = 4;
	}
	conf->hide_empty_tokens = 1;
	conf->atomic = 0;
	conf->lock_login = 0;
	conf->init_sloppy = 1;
	conf->pin_unblock_style = SC_PKCS11_PIN_UNBLOCK_NOT_ALLOWED;
	conf->create_puk_slot = 0;
	conf->zero_ckaid_for_ca_certs = 0;
	conf->create_slots_flags = SC_PKCS11_SLOT_CREATE_ALL;

	conf_block = sc_get_conf_block(ctx, "pkcs11", NULL, 1);
	if (!conf_block)
		return;

	/* contains the defaults, if there is a "pkcs11" config block */
	conf->max_virtual_slots = scconf_get_int(conf_block, "max_virtual_slots", conf->max_virtual_slots);
	conf->slots_per_card = scconf_get_int(conf_block, "slots_per_card", conf->slots_per_card);
	conf->hide_empty_tokens = scconf_get_bool(conf_block, "hide_empty_tokens", conf->hide_empty_tokens);
	conf->atomic = scconf_get_bool(conf_block, "atomic", conf->atomic);
	if (conf->atomic)
		conf->lock_login = 1;
	conf->lock_login = scconf_get_bool(conf_block, "lock_login", conf->lock_login);
	conf->init_sloppy = scconf_get_bool(conf_block, "init_sloppy", conf->init_sloppy);

	unblock_style = (char *)scconf_get_str(conf_block, "user_pin_unblock_style", NULL);
	if (unblock_style && !strcmp(unblock_style, "set_pin_in_unlogged_session"))
		conf->pin_unblock_style = SC_PKCS11_PIN_UNBLOCK_UNLOGGED_SETPIN;
	else if (unblock_style && !strcmp(unblock_style, "set_pin_in_specific_context"))
		conf->pin_unblock_style = SC_PKCS11_PIN_UNBLOCK_SCONTEXT_SETPIN;
	else if (unblock_style && !strcmp(unblock_style, "init_pin_in_so_session"))
		conf->pin_unblock_style = SC_PKCS11_PIN_UNBLOCK_SO_LOGGED_INITPIN;

	conf->create_puk_slot = scconf_get_bool(conf_block, "create_puk_slot", conf->create_puk_slot);
	conf->zero_ckaid_for_ca_certs = scconf_get_bool(conf_block, "zero_ckaid_for_ca_certs", conf->zero_ckaid_for_ca_certs);

	create_slots_for_pins = (char *)scconf_get_str(conf_block, "create_slots_for_pins", "all");
	conf->create_slots_flags = 0;
	tmp = strdup(create_slots_for_pins);
	op = strtok(tmp, " ,");
	while (op) {
		if (!strcmp(op, "user"))
			conf->create_slots_flags |= SC_PKCS11_SLOT_FOR_PIN_USER;
		else if (!strcmp(op, "sign"))
			conf->create_slots_flags |= SC_PKCS11_SLOT_FOR_PIN_SIGN;
		else if (!strcmp(op, "all"))
			conf->create_slots_flags |= SC_PKCS11_SLOT_CREATE_ALL;
		op = strtok(NULL, " ,");
	}
        free(tmp);

	sc_log(ctx, "PKCS#11 options: max_virtual_slots=%d slots_per_card=%d "
		 "hide_empty_tokens=%d lock_login=%d atomic=%d pin_unblock_style=%d "
		 "zero_ckaid_for_ca_certs=%d create_slots_flags=0x%X",
		 conf->max_virtual_slots, conf->slots_per_card,
		 conf->hide_empty_tokens, conf->lock_login, conf->atomic, conf->pin_unblock_style,
		 conf->zero_ckaid_for_ca_certs, conf->create_slots_flags);
}
