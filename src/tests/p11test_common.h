#ifndef P11TEST_COMMON_H
#define P11TEST_COMMON_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>
#include "pkcs11/pkcs11.h"

#ifdef NDEBUG
	#define debug_print(fmt, ...) \
		{ fprintf(stderr, fmt "\n", ##__VA_ARGS__); } while (0)
#else
	#define debug_print(fmt, ...)
#endif

typedef struct {
	CK_FUNCTION_LIST_PTR function_pointer;
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session_handle;
	CK_UTF8CHAR* pin;
	size_t pin_length;
	char* library_path;
} token_info_t;

#endif /* P11TEST_COMMON_H */

