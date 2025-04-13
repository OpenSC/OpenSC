#ifndef PKCS11TEST_FUNC_H
#define PKCS11TEST_FUNC_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "pkcs11/pkcs11.h"
#include "pkcs11test_types.h"
#include "pkcs11test_params_parse.h"
#include "pkcs11test_params_check.h"
#include "pkcs11test_value_check.h"

extern struct function_mapping mappings[];

process_func get_pkcs11_function(const char *name);

int process_C_Initialize(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);
int process_C_Finalize(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);
int process_C_GetInfo(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);
int process_C_GetFunctionList(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);

int process_C_GetSlotList(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);
int process_C_GetSlotInfo(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);
int process_C_GetTokenInfo(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);
int process_C_GetMechanismList(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);
int process_C_GetMechanismInfo(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);

int process_C_OpenSession(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);
int process_C_CloseSession(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);
int process_C_CloseAllSessions(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);
int process_C_Login(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);
int process_C_Logout(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);

int process_C_FindObjectsInit(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);
int process_C_FindObjects(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);
int process_C_FindObjectsFinal(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);
int process_C_GetAttributeValue(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);


int process_C_SignInit(xmlNode *calling_node, xmlNode *return_node,	struct internal_data **data, struct test_info *info);
int process_C_Sign(xmlNode *calling_node, xmlNode *return_node,	struct internal_data **data, struct test_info *info);
int process_C_SignFinal(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info);

#endif // PKCS11TEST_FUNC_H
