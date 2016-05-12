#ifndef P11TEST_COMMON_H
#define P11TEST_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "pkcs11/pkcs11.h"

#ifdef NDEBUG
	#define debug_print(fmt, ...) \
		{ fprintf(stderr, fmt "\n", ##__VA_ARGS__); } while (0)
#else
	#define debug_print(fmt, ...)
#endif

#define BUFFER_SIZE		4096
#define DEFAULT_PIN		"123456"
#define DEFAULT_P11LIB	"../pkcs11/.libs/opensc-pkcs11.so"
#define SHORT_MESSAGE_TO_SIGN "Simple message for signing & verifying.\n"

#define VERIFY_SIGN		0x02
#define VERIFY_DECRYPT	0x04

typedef struct {
	CK_MECHANISM_TYPE mech;
	int flags;
} test_mech_t;

typedef struct {
	char	*key_id;
	CK_ULONG key_id_size;
	char	*id_str;
	X509	*x509;
	int		 type;
	union {
		RSA		*rsa;
		EC_KEY	*ec;
	} key;
	CK_OBJECT_HANDLE private_handle;
	CK_BBOOL	sign;
	CK_BBOOL	decrypt;
	CK_BBOOL	verify;
	CK_BBOOL	encrypt;
	CK_KEY_TYPE	key_type;
	CK_BBOOL	always_auth;
	char		*label;
	CK_ULONG 	 bits;
	int			verify_public;
	test_mech_t	*mechs;
	int			num_mechs;
} test_cert_t;

typedef struct {
	unsigned int count;
	test_cert_t *data;
} test_certs_t;

typedef struct {
	CK_UTF8CHAR* pin;
	size_t pin_length;
} card_info_t;
card_info_t card_info;

typedef struct {
	CK_FLAGS flags;
} supported_mechanisms_t;

typedef struct {
	CK_FUNCTION_LIST_PTR function_pointer;
	CK_SLOT_ID slot_id;
	CK_SESSION_HANDLE session_handle;
	supported_mechanisms_t supported;

} token_info_t;

void display_usage();
int set_card_info();
void clear_card_info();
void init_card_info();

#endif //P11TEST_COMMON_H
