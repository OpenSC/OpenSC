#ifndef P11TEST_CASE_COMMON_H
#define P11TEST_CASE_COMMON_H

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include "p11test_common.h"

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

int search_objects(test_certs_t *objects, token_info_t *info,
	CK_ATTRIBUTE filter[], CK_LONG filter_size, CK_ATTRIBUTE template[], CK_LONG template_size,
	int (*callback)(test_certs_t *, CK_ATTRIBUTE[], unsigned int, CK_OBJECT_HANDLE));
void search_for_all_objects(test_certs_t *objects, token_info_t *info);
void clean_all_objects(test_certs_t *objects);

const char *get_mechanism_name(int mech_id);
const char *get_mechanism_flag_name(int flag_id);
char *convert_byte_string(char *id, unsigned long length);

#endif /* P11TEST_CASE_COMMON_H */
