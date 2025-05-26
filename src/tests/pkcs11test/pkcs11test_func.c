#include "pkcs11test_func.h"

struct function_mapping mappings[] = {
	/* General Cryptoki purpose functions */
    {"C_Initialize", process_C_Initialize},
    {"C_Finalize", process_C_Finalize},
	{"C_GetInfo" , process_C_GetInfo},
	{"C_GetFunctionList", process_C_GetFunctionList},
	/* Slot and token management functions */
	{"C_GetSlotList", process_C_GetSlotList},
	{"C_GetSlotInfo", process_C_GetSlotInfo},
	{"C_GetTokenInfo", process_C_GetTokenInfo},
	{"C_GetMechanismList", process_C_GetMechanismList},
	{"C_GetMechanismInfo", process_C_GetMechanismInfo},
	/* Session management functions */
	{"C_OpenSession", process_C_OpenSession},
	{"C_CloseSession", process_C_CloseSession},
	{"C_CloseAllSessions", process_C_CloseAllSessions},
	{"C_Login", process_C_Login},
	{"C_Logout", process_C_Logout},
	/* Object management functions */
	{"C_FindObjectsInit", process_C_FindObjectsInit},
	{"C_FindObjects", process_C_FindObjects},
	{"C_FindObjectsFinal", process_C_FindObjectsFinal},
	{"C_GetAttributeValue", process_C_GetAttributeValue},
	/* Signing and MACing functions*/
	{"C_SignInit", process_C_SignInit},
	{"C_Sign", process_C_Sign},
	{"C_SignUpdate", NULL},
	{"C_SignFinal", NULL},
    {NULL, NULL}
};

process_func
get_pkcs11_function(const char *name)
{
	for (int i = 0; mappings[i].name != NULL; i++) {
		if (strcmp(mappings[i].name, name) == 0) {
			return mappings[i].process_func;
		}
	}
	return NULL;
}

/* General Cryptoki purpose functions */
int
process_C_Initialize(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info)
{
	CK_C_INITIALIZE_ARGS args = { 0 };
	CK_RV actual_rv;
	int r;

	struct param_parse_map in_map[] = {
		{"InitializeArgs", &args, NULL, parse_CK_C_INITIALIZE_ARGS},
		{NULL, NULL, NULL, NULL}
	};

	log("C_Initialize: started processing");

	r = parse_params(info, data, calling_node, in_map);
	if (r != PKCS11TEST_SUCCESS) {
		return r;
	}
	actual_rv = info->pkcs11->C_Initialize(&args);
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	return r;
}

int
process_C_GetInfo(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info)
{
	CK_INFO info_arg = { 0 };
	CK_RV actual_rv;
	int r;
	struct param_check_map map[] = {
		{"Info", &info_arg, NULL, test_CK_INFO},
		{NULL, NULL, NULL, NULL}
	};
	
	log("C_Get_info: started processing");

	/* Call C_GetInfo*/
	actual_rv = info->pkcs11->C_GetInfo(&info_arg);

	/* Check return values */
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	r = test_params(info, data, return_node, map);
	return r;
}

int
process_C_GetFunctionList(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info)
{
	log("Processing C_GetFunctionList not implemented");
	return PKCS11TEST_SUCCESS;
}

int
process_C_Finalize(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info)
{
	CK_VOID_PTR ptrArgs = NULL_PTR;
	CK_RV actual_rv;
	int r;

	log("Processing C_Finalize function");
	actual_rv = info->pkcs11->C_Finalize(ptrArgs);
	r = test_CK_RV(info, data, return_node, &actual_rv, NULL);
	return r;
}

/* Slot and token management functions */
int
process_C_GetSlotList(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info)
{
	CK_RV actual_rv;
    CK_BBOOL token_present = CK_FALSE;
    CK_SLOT_ID_PTR slot_list = NULL_PTR;
    CK_ULONG count;
	int r;

	struct param_parse_map in_map[] = {
		{"TokenPresent", &token_present, NULL, parse_CK_BBOOL},
		{"SlotList", &slot_list, &count, parse_CK_SLOT_ID_PTR},
		{NULL, NULL, NULL, NULL}
	};
	struct param_check_map out_map[] = {
		{"SlotList", &slot_list, &count, test_CK_SLOT_ID_PTR},
		{NULL, NULL, NULL, NULL}
	};

	log("Processing C_GetSlotList function");
	r = parse_params(info, data, calling_node, in_map);
	if (r != PKCS11TEST_SUCCESS) {
		return r;
	}
	actual_rv = info->pkcs11->C_GetSlotList(token_present, slot_list, &count);
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	r = test_params(info, data, return_node, out_map);
	free(slot_list);
	return r;
}

int
process_C_GetSlotInfo(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info)
{
	CK_RV actual_rv;
	CK_SLOT_ID slot_id = 0;
	CK_SLOT_INFO slot_info = { 0 };
	int r;

	struct param_parse_map in_map[] = {
		{"SlotID", &slot_id, NULL, parse_CK_ULONG},
		{NULL, NULL, NULL, NULL}
	};
	struct param_check_map out_map[] = {
		{"Info", &slot_info, NULL, test_CK_SLOT_INFO},
		{NULL, NULL, NULL, NULL}
	};

	log("Processing C_GetSlotInfo function");
	r = parse_params(info, data, calling_node, in_map);
	if (r != PKCS11TEST_SUCCESS) {
		return r;
	}
	actual_rv = info->pkcs11->C_GetSlotInfo(slot_id, &slot_info);
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	r = test_params(info, data, return_node, out_map);
	return r;
}

int
process_C_GetTokenInfo(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info)
{
	CK_RV actual_rv;
	CK_SLOT_ID slot_id = 0;
	CK_TOKEN_INFO token_info = { 0 };
	int r;

	struct param_parse_map in_map[] = {
		{"SlotID", &slot_id, NULL, parse_CK_ULONG},
		{NULL, NULL, NULL, NULL}
	};
	struct param_check_map out_map[] = {
		{"Info", &token_info, NULL, test_CK_TOKEN_INFO},
		{NULL, NULL, NULL, NULL}
	};

	log("Processing C_GetTokenInfo function");
	r = parse_params(info, data, calling_node, in_map);
	if (r != PKCS11TEST_SUCCESS) {
		return r;
	}
	actual_rv = info->pkcs11->C_GetTokenInfo(slot_id, &token_info);
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	r = test_params(info, data, return_node, out_map);
	return r;
}

int
process_C_GetMechanismList(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info)
{
	CK_RV actual_rv;
	CK_SLOT_ID slot_id = 0;
	CK_MECHANISM_TYPE_PTR mechanism_list = NULL_PTR;
	CK_ULONG pul_count = 0;
	int r;
	struct param_parse_map in_map[] = {
		{"SlotID", &slot_id, NULL, parse_CK_ULONG},
		{"MechanismList", &mechanism_list, &pul_count, parse_CK_MECHANISM_TYPE_PTR},
		{NULL, NULL, NULL, NULL}
	};
	struct param_check_map out_map[] = {
		{"MechanismList", &mechanism_list, &pul_count, test_CK_MECHANISM_TYPE_PTR},
		{NULL, NULL, NULL, NULL}
	};

	log("Processing C_GetMechanismList function");
	r = parse_params(info, data, calling_node, in_map);
	if (r != PKCS11TEST_SUCCESS) {
		return r;
	}
	actual_rv = info->pkcs11->C_GetMechanismList(slot_id, mechanism_list, &pul_count);
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	r = test_params(info, data, return_node, out_map);
	return r;
}

int
process_C_GetMechanismInfo(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info)
{
	CK_RV actual_rv;
	CK_SLOT_ID slot_id = 0;
	CK_MECHANISM_TYPE type = 0;
	CK_MECHANISM_INFO mechanism_info = { 0 };
	int r;
	struct param_parse_map in_map[] = {
		{"SlotID", &slot_id, NULL, parse_CK_ULONG},
		{"Type", &type, NULL, parse_CK_MECHANISM_TYPE},
		{NULL, NULL, NULL, NULL}
	};
	struct param_check_map out_map[] = {
		{"Info", &mechanism_info, NULL, test_CK_MECHANISM_INFO},
		{NULL, NULL, NULL, NULL}
	};

	log("Processing C_GetMechanismInfo function");
	r = parse_params(info, data, calling_node, in_map);
	if (r != PKCS11TEST_SUCCESS) {
		return r;
	}
	actual_rv = info->pkcs11->C_GetMechanismInfo(slot_id, type, &mechanism_info);
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	r = test_params(info, data, return_node, out_map);
	return r;
}

/* Session management functions */
int
process_C_OpenSession(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info)
{
	CK_RV actual_rv;
	CK_SLOT_ID slot_id = 0;
	CK_FLAGS flags = 0;
	CK_VOID_PTR app = NULL_PTR;
	CK_NOTIFY notify = NULL_PTR; // omitted
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	int r;

	struct param_parse_map in_map[] = {
		{"SlotID", &slot_id, NULL, parse_CK_ULONG},
		{"Flags", &flags, NULL, parse_CK_FLAGS},
		{NULL, NULL, NULL, NULL}
	};
	struct param_check_map out_map[] = {
		{"Session", &session, NULL, test_CK_SESSION_HANDLE},
		{NULL, NULL, NULL, NULL}
	};

	log("Processing C_OpenSession function");
	r = parse_params(info, data, calling_node, in_map);
	if (r != PKCS11TEST_SUCCESS) {
		return r;
	}
	actual_rv = info->pkcs11->C_OpenSession(slot_id, flags, app, notify, &session);
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	r = test_params(info, data, return_node, out_map);
	return r;
}

int
process_C_CloseSession(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info)
{
	CK_RV actual_rv;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	int r;

	struct param_parse_map in_map[] = {
		{"Session", &session, NULL, parse_CK_SESSION_HANDLE},
		{NULL, NULL, NULL, NULL}
	};

	log("Processing C_CloseSession function");
	r = parse_params(info, data, calling_node, in_map);
	if (r != PKCS11TEST_SUCCESS) {
		return r;
	}
	actual_rv = info->pkcs11->C_CloseSession(session);
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	return r;
}

int
process_C_CloseAllSessions(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info)
{
	CK_RV actual_rv;
	CK_SLOT_ID slot_id = 0;
	int r;
	struct param_parse_map in_map[] = {
		{"SlotID", &slot_id, NULL, parse_CK_ULONG},
		{NULL, NULL, NULL, NULL}
	};

	log("Processing C_CloseAllSessions function");
	r = parse_params(info, data, calling_node, in_map);
	if (r != PKCS11TEST_SUCCESS) {
		return r;
	}
	actual_rv = info->pkcs11->C_CloseAllSessions(slot_id);
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	return r;
}

int
process_C_Login(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info)
{
	CK_RV actual_rv;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_USER_TYPE user_type = CKU_USER;
	CK_UTF8CHAR_PTR pin = NULL_PTR;
	CK_ULONG pin_len = 0;
	int r;

	struct param_parse_map in_map[] = {
		{"Session", &session, NULL, parse_CK_SESSION_HANDLE},
		{"UserType", &user_type, NULL, parse_CK_USER_TYPE},
		{"Pin", &pin, &pin_len, parse_CK_UTF8CHAR_PTR},
		{NULL, NULL, NULL, NULL}
	};
	log("Processing C_Login function");
	r = parse_params(info, data, calling_node, in_map);
	if (r != PKCS11TEST_SUCCESS) {
		return r;
	}
	actual_rv = info->pkcs11->C_Login(session, user_type, pin, pin_len);
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	return r;
}

int
process_C_Logout(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info)
{
	CK_RV actual_rv;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	int r;
	struct param_parse_map in_map[] = {
		{"Session", &session, NULL, parse_CK_SESSION_HANDLE},
		{NULL, NULL, NULL, NULL}
	};
	log("Processing C_Logout function");
	r = parse_params(info, data, calling_node, in_map);
	if (r != PKCS11TEST_SUCCESS) {
		return r;
	}
	actual_rv = info->pkcs11->C_Logout(session);
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	return PKCS11TEST_SUCCESS;
}

/* Objects management functions */
int
process_C_FindObjectsInit(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info)
{
	CK_RV actual_rv;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_ATTRIBUTE_PTR template = NULL_PTR;
	CK_ULONG count = 0;
	int r;
	struct param_parse_map in_map[] = {
		{"Session", &session, NULL, parse_CK_SESSION_HANDLE},
		{"Template", &template, &count, parse_CK_ATTRIBUTE_PTR},
		{NULL, NULL, NULL, NULL}
	};

	log("Processing C_FindObjectsInit function");
	r = parse_params(info, data, calling_node, in_map);
	if (r != PKCS11TEST_SUCCESS) {
		return r;
	}
	actual_rv = info->pkcs11->C_FindObjectsInit(session, template, count);
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	return PKCS11TEST_SUCCESS;
}

int
process_C_FindObjects(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info)
{
	CK_RV actual_rv;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE_PTR objects = NULL_PTR;
	CK_ULONG max_object_count = 0;
	CK_ULONG pul_object_count = 0;
	int r;
	struct param_parse_map in_map[] = {
		{"Session", &session, NULL, parse_CK_SESSION_HANDLE},
		{"Object", &objects, &max_object_count, parse_CK_OBJECT_HANDLE_PTR},
		{NULL, NULL, NULL, NULL}
	};
	struct param_check_map out_map[] = {
		{"Object", objects, &pul_object_count, test_CK_OBJECT_HANDLE_PTR},
		{NULL, NULL, NULL, NULL}
	};

	log("Processing C_FindObjects function");
	r = parse_params(info, data, calling_node, in_map);
	if (r != PKCS11TEST_SUCCESS) {
		return r;
	}
	actual_rv = info->pkcs11->C_FindObjects(session, objects, max_object_count, &pul_object_count);
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	r = test_params(info, data, return_node, out_map);
	return r;
}

int
process_C_FindObjectsFinal(xmlNode *calling_node, xmlNode *return_node, struct internal_data **data, struct test_info *info)
{
	CK_RV actual_rv;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	int r;
	struct param_parse_map in_map[] = {
		{"Session", &session, NULL, parse_CK_SESSION_HANDLE},
		{NULL, NULL, NULL, NULL}
	};
	log("Processing C_FindObjectsFinal function");
	r = parse_params(info, data, calling_node, in_map);
	if (r != PKCS11TEST_SUCCESS) {
		return r;
	}
	actual_rv = info->pkcs11->C_FindObjectsFinal(session);
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	return r;
}

int
process_C_GetAttributeValue(xmlNode *calling_node, xmlNode *return_node,
		struct internal_data **data, struct test_info *info)
{
	CK_RV actual_rv;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
	CK_ATTRIBUTE_PTR template = NULL_PTR;
	CK_ULONG count = 0;
	int r;

	struct param_parse_map in_map[] = {
		{"Session", &session, NULL, parse_CK_SESSION_HANDLE},
		{"Object", &object, NULL, parse_CK_ULONG},
		{"Template", &template, &count, parse_CK_ATTRIBUTE_PTR},
		{NULL, NULL, NULL, NULL}
	};
	struct param_check_map out_map[] = {
		{"Template", &template, &count, test_CK_ATTRIBUTE_PTR},
		{NULL, NULL, NULL, NULL}
	};

	log("Processing C_GetAttributeValue function");
	r = parse_params(info, data, calling_node, in_map);
	if (r != PKCS11TEST_SUCCESS) {
		return r;
	}
	actual_rv = info->pkcs11->C_GetAttributeValue(session, object, template, count);
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	r = test_params(info, data, return_node, out_map);
	return r;
}

/* Signing and MACing functions*/
int process_C_SignInit(xmlNode *calling_node, xmlNode *return_node,
		struct internal_data **data, struct test_info *info)
{
	CK_RV actual_rv;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_MECHANISM mechanism = { 0 };
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	int r;

	struct param_parse_map in_map[] = {
		{"Session", &session, NULL, parse_CK_SESSION_HANDLE},
		{"Mechanism", &mechanism, NULL, parse_CK_MECHANISM},
		{"Key", &key, NULL, parse_CK_ULONG},
		{NULL, NULL, NULL, NULL}
	};
	
	log("Processing C_SignInit function");
	r = parse_params(info, data, calling_node, in_map);
	if (r != PKCS11TEST_SUCCESS) {
		return r;
	}
	actual_rv = info->pkcs11->C_SignInit(session, &mechanism, key);
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	return r;
}

int process_C_Sign(xmlNode *calling_node, xmlNode *return_node,
		struct internal_data **data, struct test_info *info)
{
	CK_RV actual_rv;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_BYTE_PTR sign_data = NULL_PTR;
	CK_ULONG sign_data_len = 0;
	CK_BYTE_PTR signature = NULL_PTR;
	CK_ULONG signature_len = 0;
	int r;

	struct param_parse_map in_map[] = {
		{"Session", &session, NULL, parse_CK_SESSION_HANDLE},
		{"Data", &sign_data, &sign_data_len, parse_CK_BYTE_PTR},
		{"Signature", &signature, &signature_len, parse_CK_BYTE_PTR},
		{NULL, NULL, NULL, NULL}
	};
	struct param_check_map out_map[] = {
		{"Signature", &signature, &signature_len, test_CK_BYTE_PTR},
		{NULL, NULL, NULL, NULL}
	};

	log("Processing C_Sign function");
	r = parse_params(info, data, calling_node, in_map);
	if (r != PKCS11TEST_SUCCESS) {
		return r;
	}
	actual_rv = info->pkcs11->C_Sign(session, sign_data, sign_data_len, signature, &signature_len);
	test_CK_RV(info, data, return_node, &actual_rv, NULL);
	r = test_params(info, data, return_node, out_map);
	return r;
}
