/*
 * sc-pkcs11.c: PKCS#11 library header file
 *
 * Copyright (C) 2001  Timo Teräs <timo.teras@iki.fi>
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

#ifndef __sc_pkcs11_h__
#define __sc_pkcs11_h__

#include <winscard.h>

#include "pkcs11/pkcs11.h"
#include <opensc.h>
#include <opensc-pkcs15.h>

#define PKCS11_MAX_SLOTS        4
#define PKCS11_MAX_SESSIONS     8
#define PKCS11_MAX_OBJECTS      16

/* Object information */
struct pkcs11_object {
        int object_type, token_id;
        int num_attributes;
	CK_ATTRIBUTE_PTR attribute;
};

/* Search information */
struct pkcs11_search_context {
        int num_matches, position;
        CK_OBJECT_HANDLE handles[PKCS11_MAX_OBJECTS];
};

/* Signing information */
struct pkcs11_sign_context {
	int private_key_id;
        int algorithm_ref;
};

/* Per session information; "context" */
struct pkcs11_session {
	int slot;
	CK_STATE state;
        CK_FLAGS flags;
	CK_NOTIFY notify_callback;
	CK_VOID_PTR notify_parameter;

	struct pkcs11_search_context search;
        struct pkcs11_sign_context sign;
        /* ... */
};

/* Per slot (=card) information */
#define SLOT_CONNECTED 1
#define SLOT_LOGGED_IN 2

struct pkcs11_slot {
        int flags;
	struct sc_pkcs15_card *p15card;

        int num_objects;
	struct pkcs11_object *object[PKCS11_MAX_OBJECTS+1];
};

extern CK_FUNCTION_LIST function_list;
extern void LOG(char *format, ...);
extern void hex_dump(const unsigned char *buf, int count);

extern struct sc_context *ctx;
extern struct pkcs11_slot slot[PKCS11_MAX_SLOTS];
extern struct pkcs11_session *session[PKCS11_MAX_SESSIONS+1];


extern int slot_connect(int id);
extern int slot_disconnect(int id);

#endif

