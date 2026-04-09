#ifndef PKCS11TEST_PROP_CHECK_H
#define PKCS11TEST_PROP_CHECK_H

#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "pkcs11/pkcs11.h"
#include "pkcs11test_common.h"
#include "pkcs11test_prop_parse.h"
#include "pkcs11test_value_check.h"

int test_props(struct test_info *info, struct internal_data **data, xmlNode *parent_node, struct prop_check_map map[]);

int test_CK_RV_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_BYTE_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_ULONG_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_FLAGS_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_OBJECT_CLASS_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_KEY_TYPE_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_UTF8CHAR_PTR_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_CHAR_PTR_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int test_CK_BYTE_PTR_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);

#endif // PKCS11TEST_PROP_CHECK_H
