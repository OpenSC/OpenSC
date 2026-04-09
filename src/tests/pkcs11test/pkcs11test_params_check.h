#ifndef PKCS11TEST_PARAMS_H
#define PKCS11TEST_PARAMS_H

#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "pkcs11/pkcs11.h"
#include "pkcs11test_common.h"
#include "pkcs11test_params_parse.h"
#include "pkcs11test_value_check.h"
#include "pkcs11test_prop_check.h"

int test_params(struct test_info *info, struct internal_data **data, xmlNode *parent_node, struct param_check_map map[]);

/* Base structures*/
int test_CK_RV(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_UTF8CHAR_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_BYTE_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_FLAGS(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_OBJECT_CLASS(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_KEY_TYPE(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);

/* Nested structures */
int test_CK_INFO(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_SLOT_INFO(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_TOKEN_INFO(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_SESSION_HANDLE(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_MECHANISM_INFO(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);

/* List of structures */
int test_CK_SLOT_ID_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_OBJECT_HANDLE_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_ATTRIBUTE_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_MECHANISM_TYPE_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);

#endif // PKCS11TEST_PARAMS_H
