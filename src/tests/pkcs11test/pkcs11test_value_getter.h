#ifndef PKCS11TEST_VALUE_GETTER_H
#define PKCS11TEST_VALUE_GETTER_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "pkcs11/pkcs11.h"
#include "pkcs11test_types.h"
#include "pkcs11test_str.h"

int get_CK_BYTE(const char *value, CK_BYTE_PTR result);
int get_num_value(char *value, CK_ULONG *result, enum ck_type type);

int get_CK_UTF8CHAR_PTR(char *value, CK_UTF8CHAR_PTR *result, CK_ULONG_PTR length);
int get_CK_CHAR_PTR(char *value, CK_CHAR_PTR *result, CK_ULONG_PTR length);
int get_CK_BYTE_PTR(char *value, CK_BYTE_PTR *result, CK_ULONG_PTR length);

#endif // PKCS11TEST_VALUE_GETTER_H
