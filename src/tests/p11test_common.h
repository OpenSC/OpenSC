#ifndef P11TEST_COMMON_H
#define P11TEST_COMMON_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>
#include "pkcs11/pkcs11.h"

#define MAX_MECHS 5

#ifdef NDEBUG
	#define debug_print(fmt, ...) \
		{ fprintf(stderr, fmt "\n", ##__VA_ARGS__); } while (0)
#else
	#define debug_print(fmt, ...)
#endif

typedef struct {
	CK_MECHANISM_TYPE mech;
	int flags;
} test_mech_t;

typedef struct {
	CK_FUNCTION_LIST_PTR function_pointer;
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session_handle;
	CK_UTF8CHAR* pin;
	size_t pin_length;
	char* library_path;
	test_mech_t rsa_mechs[MAX_MECHS];
	size_t  num_rsa_mechs;
	test_mech_t	ec_mechs[MAX_MECHS];
	size_t  num_ec_mechs;
} token_info_t;

token_info_t token;

#endif /* P11TEST_COMMON_H */

