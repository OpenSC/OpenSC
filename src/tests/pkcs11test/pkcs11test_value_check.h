#ifndef PKCS11TEST_VALUE_CHECK_H
#define PKCS11TEST_VALUE_CHECK_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "pkcs11/pkcs11.h"
#include "pkcs11test_types.h"
#include "pkcs11test_str.h"

int check_num_value(CK_ULONG expected, CK_ULONG actual, enum ck_type type);
int check_memory(CK_BYTE_PTR expected, CK_BYTE_PTR actual, size_t length);
int check_CK_BYTE(CK_BYTE expected, CK_BYTE actual);

#endif // PKCS11TEST_VALUE_CHECK_H