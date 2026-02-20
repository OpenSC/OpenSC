#ifndef PKCS11TEST_STRUCT_PARSER_H
#define PKCS11TEST_STRUCT_PARSER_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "pkcs11/pkcs11.h"
#include "pkcs11test_types.h"
#include "pkcs11test_prop_parse.h"
#include "pkcs11test_value_check.h"

int parse_params(struct test_info *info, struct internal_data **data,
		xmlNode *parent_node, struct param_parse_map map[]);

/* Non-nested structures types*/
int parse_CK_BBOOL(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_ULONG(struct test_info *info, struct internal_data **data,	xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_FLAGS(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_USER_TYPE(struct test_info *info, struct internal_data **data,	xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_UTF8CHAR_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_CHAR_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_BYTE_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_SESSION_HANDLE(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_MECHANISM_TYPE(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_MECHANISM(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_ATTRIBUTE(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR type);

/* Nested structures types*/
int parse_CK_C_INITIALIZE_ARGS(struct test_info *, struct internal_data **, xmlNode *, CK_VOID_PTR, CK_ULONG_PTR);
int parse_CK_VERSION(struct test_info *, struct internal_data **, xmlNode *, CK_VOID_PTR, CK_ULONG_PTR);
int parse_CK_SLOT_ID_PTR(struct test_info *, struct internal_data **, xmlNode *, CK_VOID_PTR, CK_ULONG_PTR);

/* List types*/
int parse_CK_ATTRIBUTE_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_OBJECT_HANDLE_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);
int parse_CK_MECHANISM_TYPE_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length);

#endif // PKCS11TEST_STRUCT_PARSER_H
