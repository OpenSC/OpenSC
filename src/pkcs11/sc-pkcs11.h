/*
 * opensc-pkcs11.h: OpenSC project's PKCS#11 implementation header
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

#ifndef __opensc_pkcs11_h__
#define __opensc_pkcs11_h__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <opensc/opensc.h>
#include <opensc/pkcs15.h>
#include <opensc/log.h>
#include "rsaref/pkcs11.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SC_PKCS11_MAX_VIRTUAL_SLOTS	4
#define SC_PKCS11_MAX_READERS           2

struct sc_pkcs11_session;
struct sc_pkcs11_slot;
struct sc_pkcs11_card;

/* Object Pool */
struct sc_pkcs11_pool_item {
	int handle;
        void *item;
	struct sc_pkcs11_pool_item *next;
        struct sc_pkcs11_pool_item *prev;
};

struct sc_pkcs11_pool {
        int next_free_handle;
	int num_items;
	struct sc_pkcs11_pool_item *head;
        struct sc_pkcs11_pool_item *tail;
};


/*
 * PKCS#11 Object abstraction layer
 */

struct sc_pkcs11_object_ops {
        /* Generic operations */
        void (*release)(void *);

        /* Management methods */
	CK_RV (*set_attribute)(struct sc_pkcs11_session *, void *, CK_ATTRIBUTE_PTR);
	CK_RV (*get_attribute)(struct sc_pkcs11_session *, void *, CK_ATTRIBUTE_PTR);
	int   (*cmp_attribute)(struct sc_pkcs11_session *, void *, CK_ATTRIBUTE_PTR);

	CK_RV (*destroy_object)(struct sc_pkcs11_session *, void *);
        CK_RV (*get_size)(struct sc_pkcs11_session *, void *);

	/* Cryptographic methods */
	CK_RV (*sign)(struct sc_pkcs11_session *, void *, CK_MECHANISM_PTR pMechanism, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulDataLen);
	CK_RV (*unwrap_key)(struct sc_pkcs11_session *, void *,
			CK_MECHANISM_PTR,
			CK_BYTE_PTR pData, CK_ULONG ulDataLen,
			CK_ATTRIBUTE_PTR, CK_ULONG,
			void **);
        /* Others to be added when implemented */
};

struct sc_pkcs11_object {
        struct sc_pkcs11_object_ops *ops;
};


/*
 * PKCS#11 Smartcard Framework abstraction
 */

struct sc_pkcs11_framework_ops {
        /* Detect and bind card to framework */
	CK_RV (*bind)(struct sc_pkcs11_card *);
        /* Unbind and release allocated resources */
	CK_RV (*unbind)(struct sc_pkcs11_card *);

	/* Create tokens to virtual slots and
	 * objects in tokens; called after bind */
	CK_RV (*create_tokens)(struct sc_pkcs11_card *);
        CK_RV (*release_token)(struct sc_pkcs11_card *, void *);

	/* Methods to ask about supported object ops */
	CK_RV (*get_mechanism_list)(struct sc_pkcs11_card *, void *, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
        CK_RV (*get_mechanism_info)(struct sc_pkcs11_card *, void *, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);

	/* Login and logout */
	CK_RV (*login)(struct sc_pkcs11_card *, void *,
				CK_USER_TYPE, CK_CHAR_PTR, CK_ULONG);
        CK_RV (*logout)(struct sc_pkcs11_card *, void *);
	CK_RV (*change_pin)(struct sc_pkcs11_card *, void *,
				CK_CHAR_PTR, CK_ULONG,
				CK_CHAR_PTR, CK_ULONG);

	/*
	 * In future: functions to create new objects
	 * (ie. certificates, private keys)
         */
	CK_RV (*init_token)(struct sc_pkcs11_card *, void *,
				CK_UTF8CHAR_PTR, CK_ULONG,
				CK_UTF8CHAR_PTR);
	CK_RV (*init_pin)(struct sc_pkcs11_card *,
				struct sc_pkcs11_slot *,
				CK_UTF8CHAR_PTR, CK_ULONG);
	CK_RV (*create_object)(struct sc_pkcs11_card *,
				struct sc_pkcs11_slot *,
				CK_ATTRIBUTE_PTR, CK_ULONG,
				CK_OBJECT_HANDLE_PTR);
};


/*
 * PKCS#11 Slot (used to access card with specific framework data)
 */

struct sc_pkcs11_card {
        int reader;
	struct sc_card *card;
        struct sc_pkcs11_framework_ops *framework;
	void *fw_data;
};

struct sc_pkcs11_slot {
	int id;
        int login_user;
        /* Slot specific information (information about reader) */
	CK_SLOT_INFO slot_info;
	/* Token specific information (information about card) */
        CK_TOKEN_INFO token_info;
        /* The card associated with this slot */
	struct sc_pkcs11_card *card;
	/* Framework specific data */
	void *fw_data;
	/* Object pools */
	struct sc_pkcs11_pool object_pool;
	/* Number of sessions using this slot */
	unsigned int nsessions;
};


struct sc_pkcs11_operation {
        int type;
};

#define SC_PKCS11_OPERATION_FIND        1
#define SC_PKCS11_OPERATION_SIGN        2

struct sc_pkcs11_sign_operation {
        struct sc_pkcs11_operation operation;
	struct sc_pkcs11_object *key;
        CK_MECHANISM mechanism;
};

#define SC_PKCS11_FIND_MAX_HANDLES	32

struct sc_pkcs11_find_operation {
	struct sc_pkcs11_operation operation;
        int num_handles, current_handle;
        CK_OBJECT_HANDLE handles[SC_PKCS11_FIND_MAX_HANDLES];
};

/*
 * PKCS#11 Session
 */

struct sc_pkcs11_session {
	/* Session to this slot */
	struct sc_pkcs11_slot *slot;
        CK_FLAGS flags;
	/* Notifications */
	CK_NOTIFY notify_callback;
        CK_VOID_PTR notify_data;
	/* Active operation */
	struct sc_pkcs11_operation *operation;
};

/* Module variables */
extern struct sc_context *context;
extern struct sc_pkcs11_pool session_pool;
extern struct sc_pkcs11_slot virtual_slots[SC_PKCS11_MAX_VIRTUAL_SLOTS];
extern struct sc_pkcs11_card card_table[SC_PKCS11_MAX_READERS];

/* Framework definitions */
extern struct sc_pkcs11_framework_ops framework_pkcs15;
extern struct sc_pkcs11_framework_ops framework_pkcs15init;

void strcpy_bp(u8 *dst, const char *src, int dstsize);
CK_RV sc_to_cryptoki_error(int rc, int reader);
void dump_template(const char *info, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

/* Slot and card handling functions */
CK_RV card_initialize(int reader);
CK_RV card_detect(int reader);
CK_RV card_removed(int reader);
CK_RV slot_initialize(int id, struct sc_pkcs11_slot *);
CK_RV slot_get_slot(int id, struct sc_pkcs11_slot **);
CK_RV slot_get_token(int id, struct sc_pkcs11_slot **);
CK_RV slot_token_removed(int id);
CK_RV slot_allocate(struct sc_pkcs11_slot **, struct sc_pkcs11_card *);

/* Pool */
CK_RV pool_initialize(struct sc_pkcs11_pool *);
CK_RV pool_insert(struct sc_pkcs11_pool *, void *, CK_ULONG_PTR);
CK_RV pool_find(struct sc_pkcs11_pool *, CK_ULONG, void **);
CK_RV pool_find_and_delete(struct sc_pkcs11_pool *, CK_ULONG, void **);

/* Session manipulation */
CK_RV session_start_operation(struct sc_pkcs11_session *, int, int, struct sc_pkcs11_operation **);
CK_RV session_check_operation(struct sc_pkcs11_session *, int);
CK_RV session_stop_operation(struct sc_pkcs11_session *);

/* Generic secret key stuff */
CK_RV sc_pkcs11_create_secret_key(struct sc_pkcs11_session *,
			const u8 *, size_t,
			CK_ATTRIBUTE_PTR, CK_ULONG,
			struct sc_pkcs11_object **);
/* Generic object handling */
int sc_pkcs11_any_cmp_attribute(struct sc_pkcs11_session *,
			void *, CK_ATTRIBUTE_PTR);

/* Get attributes from template (misc.c) */
CK_RV attr_find(CK_ATTRIBUTE_PTR, CK_ULONG, CK_ULONG, void *, size_t *);
CK_RV attr_find_ptr(CK_ATTRIBUTE_PTR, CK_ULONG, CK_ULONG, void **, size_t *);
CK_RV attr_find_var(CK_ATTRIBUTE_PTR, CK_ULONG, CK_ULONG, void *, size_t *);
CK_RV attr_extract(CK_ATTRIBUTE_PTR, void *, size_t *);

#ifdef __cplusplus
}
#endif

#endif
