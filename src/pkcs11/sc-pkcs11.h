#ifndef __sc_pkcs11_h__
#define __sc_pkcs11_h__

#include <winscard.h>

#include "pkcs11/pkcs11.h"
#include "../sc.h"

#define PKCS11_MAX_SLOTS        4
#define PKCS11_MAX_SESSIONS     8
#define PKCS11_MAX_OBJECTS      16

// Object information
struct pkcs11_object {
        int num_attributes;
	CK_ATTRIBUTE_PTR attribute;
};

// Search information
struct pkcs11_search_context {
        int num_matches, position;
        CK_OBJECT_HANDLE handles[PKCS11_MAX_OBJECTS];
};

// Per session information; "context"
struct pkcs11_session {
	int slot;
	CK_STATE state;
        CK_FLAGS flags;
	CK_NOTIFY notify_callback;
	CK_VOID_PTR notify_parameter;

	struct pkcs11_search_context search;
        //...
};

// Per slot (=card) information
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

extern struct sc_context *ctx;
extern struct pkcs11_slot slot[PKCS11_MAX_SLOTS];
extern struct pkcs11_session *session[PKCS11_MAX_SESSIONS+1];


extern int slot_connect(int id);
extern int slot_disconnect(int id);

#endif

