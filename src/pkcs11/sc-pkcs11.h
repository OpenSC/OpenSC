#ifndef __sc_pkcs11_h__
#define __sc_pkcs11_h__

#include "pkcs11/pkcs11.h"
#include <winscard.h>

extern CK_FUNCTION_LIST function_list;
extern void LOG(char *format, ...);

extern SCARDCONTEXT sc_ctx;

#endif

