#ifndef __sc_pkcs11_h__
#define __sc_pkcs11_h__

#include <winscard.h>

#include "pkcs11/pkcs11.h"
#include "../sc.h"

#define PKCS11_MAX_CARDS        4
#define PKCS11_MAX_SESSIONS     8

struct pkcs11_session {
	int slot;
	CK_STATE state;
        CK_FLAGS flags;
	CK_NOTIFY notify_callback;
        CK_VOID_PTR notify_parameter;
};

extern CK_FUNCTION_LIST function_list;
extern void LOG(char *format, ...);

extern struct sc_context *ctx;
extern struct sc_pkcs15_card *p15card[PKCS11_MAX_CARDS];
extern struct pkcs11_session *session[PKCS11_MAX_SESSIONS];

#endif

