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

#include <stdlib.h>
#include <malloc.h>
#include "sc-pkcs11.h"
#include <sc-log.h>

#define DUMP_TEMPLATE_MAX	32

void strcpy_bp(u8 *dst, const char *src, int dstsize)
{
	int c = strlen(src) > dstsize ? dstsize : strlen(src);
	
	memcpy((char *) dst, src, c);
	dstsize -= c;
	memset((char *) dst + c, ' ', dstsize);
}

CK_RV sc_to_cryptoki_error(int rc, int reader)
{
	switch (rc) {
	case SC_SUCCESS:
		return CKR_OK;
	case SC_ERROR_NOT_SUPPORTED:
		return CKR_FUNCTION_NOT_SUPPORTED;
	case SC_ERROR_OUT_OF_MEMORY:
		return CKR_HOST_MEMORY;
	case SC_ERROR_PIN_CODE_INCORRECT:
		return CKR_PIN_INCORRECT;
	case SC_ERROR_BUFFER_TOO_SMALL:
		return CKR_BUFFER_TOO_SMALL;
	case SC_ERROR_CARD_NOT_PRESENT:
		card_removed(reader);
		return CKR_TOKEN_NOT_PRESENT;
	case SC_ERROR_UNKNOWN_SMARTCARD:
	case SC_ERROR_INVALID_CARD:
		return CKR_TOKEN_NOT_RECOGNIZED;
	}
	return CKR_GENERAL_ERROR;
}

void dump_template(const char *info, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	int i, j, count;

	for (i = 0; i < ulCount; i++) {
		char foo[4 * DUMP_TEMPLATE_MAX + 1] = "", *p;
		unsigned char *value = (unsigned char*) pTemplate[i].pValue;

		if (pTemplate[i].pValue) {
			count = pTemplate[i].ulValueLen;
			if (count > DUMP_TEMPLATE_MAX)
				count = DUMP_TEMPLATE_MAX;
			for (j = 0, p = foo; j < count; j++) {
				p += sprintf(p, "%02X", value[j]);
			}

			debug(context,
				"%s: Attribute 0x%x = %s%s (length=%d)\n",
				info, pTemplate[i].type, foo,
				(count < pTemplate[i].ulValueLen)? "..." : "",
				pTemplate[i].ulValueLen);
		} else {
			debug(context, "%s: Attribute 0x%x, length inquiry\n",
			    info, pTemplate[i].type);
		}
	}

}


/* Pool */
CK_RV pool_initialize(struct sc_pkcs11_pool *pool)
{
	pool->next_free_handle = 1;
	pool->num_items = 0;
	pool->head = pool->tail = NULL;

        return CKR_OK;
}

CK_RV pool_insert(struct sc_pkcs11_pool *pool, void *item_ptr, CK_ULONG_PTR pHandle)
{
	struct sc_pkcs11_pool_item *item;
        int handle = pool->next_free_handle++;

	item = (struct sc_pkcs11_pool_item*) malloc(sizeof(struct sc_pkcs11_pool_item));

	if (pHandle != NULL)
                *pHandle = handle;

        item->handle = handle;
	item->item = item_ptr;
	item->next = NULL;
        item->prev = pool->tail;

	if (pool->head != NULL && pool->tail != NULL) {
		pool->tail->next = item;
                pool->tail = item;
	} else
                pool->head = pool->tail = item;

        return CKR_OK;
}

CK_RV pool_find(struct sc_pkcs11_pool *pool, CK_ULONG handle, void **item_ptr)
{
	struct sc_pkcs11_pool_item *item;

	if (context == NULL)
                return CKR_CRYPTOKI_NOT_INITIALIZED;

	for (item = pool->head; item != NULL; item = item->next) {
		if (item->handle == handle) {
			*item_ptr = item->item;
                        return CKR_OK;
		}
	}

        return CKR_FUNCTION_FAILED;
}

CK_RV pool_find_and_delete(struct sc_pkcs11_pool *pool, CK_ULONG handle, void **item_ptr)
{
	struct sc_pkcs11_pool_item *item;

	if (context == NULL)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	for (item = pool->head; item != NULL; item = item->next) {
		if (handle == 0 || item->handle == handle) {
			if (item->prev) item->prev->next = item->next;
			if (item->next) item->next->prev = item->prev;
			if (pool->head == item) pool->head = item->next;
                        if (pool->tail == item) pool->tail = item->prev;

			*item_ptr = item->item;
                        free(item);

			return CKR_OK;
		}
	}

        return CKR_FUNCTION_FAILED;
}

/* Session manipulation */
CK_RV session_start_operation(struct sc_pkcs11_session *session, int type,
			      int size, struct sc_pkcs11_operation **operation)
{
	if (context == NULL)
                return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (session->operation != NULL)
		return CKR_OPERATION_ACTIVE;

	session->operation = (struct sc_pkcs11_operation*) malloc(size);
	session->operation->type = type;
        *operation = session->operation;

        return CKR_OK;
}

CK_RV session_check_operation(struct sc_pkcs11_session *session, int type)
{
	if (session->operation == NULL)
		return CKR_OPERATION_NOT_INITIALIZED;

	if (session->operation->type != type)
		return CKR_OPERATION_NOT_INITIALIZED;

        return CKR_OK;
}

CK_RV session_stop_operation(struct sc_pkcs11_session *session)
{
	if (session->operation == NULL)
		return CKR_OPERATION_NOT_INITIALIZED;

	free(session->operation);
	session->operation = NULL;
        return CKR_OK;
}

