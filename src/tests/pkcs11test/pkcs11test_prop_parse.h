#ifndef PKCS11TEST_PROP_PARSER_H
#define PKCS11TEST_PROP_PARSER_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "pkcs11/pkcs11.h"
#include "pkcs11test_types.h"
#include "pkcs11test_value_getter.h"
#include "pkcs11test_str.h"

int parse_props(struct test_info *info, struct internal_data **data, xmlNode *parent_node, struct prop_parse_map map[]);

/* XML node value parsers*/
int parse_CK_RV(xmlNode *node, CK_RV *rv);
int parse_CK_ULONG_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_BYTE_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_FLAGS_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_ATTRIBUTE_TYPE_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_OBJECT_CLASS_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_KEY_TYPE_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_USER_TYPE_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_UTF8CHAR_PTR_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_CHAR_PTR_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_BYTE_PTR_prop(struct test_info *info, struct internal_data **data,	xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_MECHANISM_TYPE_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length);

#endif // PKCS11TEST_PROP_PARSER_H
