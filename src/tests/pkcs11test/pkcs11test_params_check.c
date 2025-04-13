#include "pkcs11test_params_check.h"

int
test_params(struct test_info *info, struct internal_data **data, xmlNode *parent_node, struct param_check_map map[])
{
	xmlNode *node = NULL;
	int r;

	for (node = parent_node->children; node; node = node->next) { // go over all nodes
		if (node->type == XML_ELEMENT_NODE) {
			for (int i = 0; map[i].name != NULL; i++) { // go over all specified parameters in array
				if (strcmp((char *)node->name, map[i].name) == 0) {
					check_func func = map[i].check_func;
					if (func != NULL) {
						log("\t%s: Checking node against actual return value.", map[i].name);
						r = func(info, data, node, map[i].ptr, map[i].length);
						if (r != PKCS11TEST_SUCCESS) {
							return r;
						}
					}
				}
			}
		}
	}
	return PKCS11TEST_SUCCESS;
}

int
test_CK_RV(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_RV *exp_rv = (CK_RV *)ptr;
	int r;
	struct prop_check_map prop_map[] = {
		{"rv", exp_rv, NULL, test_CK_RV_prop},
		{NULL, NULL, NULL, NULL}
	};
	log("\tChecking return value.");
	r = test_props(info, data, node, prop_map);
	return r;
}

int
test_CK_FLAGS(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_FLAGS *act_flags = (CK_FLAGS *)ptr;
	int r;
	struct prop_check_map prop_map[] = {
		{"value", act_flags, NULL, test_CK_FLAGS_prop},
		{NULL, NULL, NULL, NULL}
	};
	r = test_props(info, data, node, prop_map);
	return r;
}

int
test_CK_OBJECT_CLASS(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_OBJECT_CLASS *act_class = 0;
	int r;
	struct prop_check_map prop_map[] = {
		{"value", act_class, NULL, test_CK_OBJECT_CLASS_prop},
		{NULL, NULL, NULL, NULL}
	};
	r = test_props(info, data, node, prop_map);
	return r;
}

int
test_CK_KEY_TYPE(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_KEY_TYPE *act_type = 0;
	int r;
	struct prop_check_map prop_map[] = {
		{"value", act_type, NULL, test_CK_KEY_TYPE_prop},
		{NULL, NULL, NULL, NULL}
	};
	r = test_props(info, data, node, prop_map);
	return r;
}

int
test_CK_UTF8CHAR_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_UTF8CHAR_PTR *exp_chars = (CK_UTF8CHAR_PTR *)ptr;
	int r;
	struct prop_check_map prop_map[] = {
		{"value", exp_chars, length, test_CK_UTF8CHAR_PTR_prop},
		{NULL, NULL, NULL, NULL}
	};
	r = test_props(info, data, node, prop_map);
	return r;
}

int
test_CK_CHAR_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_CHAR_PTR *exp_chars = (CK_CHAR_PTR *)ptr;
	int r;
	struct prop_check_map prop_map[] = {
		{"value", exp_chars, length, test_CK_CHAR_PTR_prop},
		{NULL, NULL, NULL, NULL}
	};
	r = test_props(info, data, node, prop_map);
	return r;
}

int
test_CK_BYTE_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_BYTE_PTR *exp_bytes = (CK_BYTE_PTR *)ptr;
	int r;
	struct prop_check_map prop_map[] = {
		{"value", exp_bytes, length, test_CK_BYTE_PTR_prop},
		{NULL, NULL, NULL, NULL}
	};
	r = test_props(info, data, node, prop_map);
	return r;
}

int
test_CK_VERSION(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_VERSION_PTR act_version = (CK_VERSION_PTR) ptr;
	int r;
	struct prop_check_map prop_map[] = {
		{"minor", &act_version->minor, NULL, test_CK_BYTE_prop},
		{"major", &act_version->major, NULL, test_CK_BYTE_prop},
		{NULL, NULL, NULL, NULL}
	};
	r = test_props(info, data, node, prop_map);
	return r;
}

int
test_CK_INFO(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_INFO_PTR info_arg = (CK_INFO_PTR)ptr;
	CK_ULONG manufacturerID_len = 32;
	CK_ULONG libraryDescription_len = 64;
	int r;
	struct param_check_map param_map[] = {
		{"CryptokiVersion", &info_arg->cryptokiVersion, NULL, test_CK_VERSION},
		{"ManufacturerID", &info_arg->manufacturerID, &manufacturerID_len, test_CK_UTF8CHAR_PTR},
		{"Flags", &info_arg->flags, NULL, test_CK_FLAGS},
		{"LibraryDescription", &info_arg->libraryDescription, &libraryDescription_len, test_CK_UTF8CHAR_PTR},
		{"LibraryVersion", &info_arg->libraryVersion, NULL, test_CK_VERSION},
		{NULL, NULL, NULL, NULL}
	};

	r = test_params(info, data, node, param_map);
	return r;
}

int
test_CK_SLOT_INFO(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_SLOT_INFO_PTR info_arg = (CK_SLOT_INFO_PTR)ptr;
	CK_ULONG manufacturerID_len = 32;
	CK_ULONG slotDescription_len = 64;
	int r;
	struct param_check_map map[] = {
		{"SlotDescription", &info_arg->slotDescription, &slotDescription_len, test_CK_UTF8CHAR_PTR},
		{"ManufacturerID", &info_arg->manufacturerID, &manufacturerID_len, test_CK_UTF8CHAR_PTR},
		{"Flags", &info_arg->flags, NULL, test_CK_FLAGS},
		{"HardwareVersion", &info_arg->hardwareVersion, NULL, test_CK_VERSION},
		{"FirmwareVersion", &info_arg->firmwareVersion, NULL, test_CK_VERSION},
		{NULL, NULL, NULL, NULL}
	};
	r = test_params(info, data, node, map);
	return r;
}

int
test_CK_TOKEN_INFO(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_TOKEN_INFO_PTR info_arg = (CK_TOKEN_INFO_PTR)ptr;
	int r;
	struct prop_check_map prop_map[] = {
		{"MaxSessionCount", &info_arg->ulMaxSessionCount, NULL, test_CK_ULONG_prop},
		{"SessionCount", &info_arg->ulSessionCount, NULL, test_CK_ULONG_prop},
		{"MaxRwSessionCount", &info_arg->ulMaxRwSessionCount, NULL, test_CK_ULONG_prop},
		{"RwSessionCount", &info_arg->ulRwSessionCount, NULL, test_CK_ULONG_prop},
		{"MaxPinLen", &info_arg->ulMaxPinLen, NULL, test_CK_ULONG_prop},
		{"MinPinLen", &info_arg->ulMinPinLen, NULL, test_CK_ULONG_prop},
		{"TotalPublicMemory", &info_arg->ulTotalPublicMemory, NULL, test_CK_ULONG_prop},
		{"FreePublicMemory", &info_arg->ulFreePublicMemory, NULL, test_CK_ULONG_prop},
		{"TotalPrivateMemory", &info_arg->ulTotalPrivateMemory, NULL, test_CK_ULONG_prop},
		{"FreePrivateMemory", &info_arg->ulFreePrivateMemory, NULL, test_CK_ULONG_prop},
		{NULL, NULL, NULL, NULL}
	};
	CK_ULONG label_len = 32;
	CK_ULONG manufacturerID_len = 32;
	CK_ULONG model_len = 16;
	CK_ULONG serialNumber_len = 16;
	CK_ULONG utcTime_len = 16;
	struct param_check_map map[] = {
		{"label", &info_arg->label, &label_len, test_CK_UTF8CHAR_PTR},
		{"ManufacturerID", &info_arg->manufacturerID, &manufacturerID_len, test_CK_UTF8CHAR_PTR},
		{"model", &info_arg->model, &model_len, test_CK_UTF8CHAR_PTR},
		{"serialNumber", &info_arg->serialNumber, &serialNumber_len, test_CK_CHAR_PTR},
		{"Flags", &info_arg->flags, NULL, test_CK_FLAGS},
		{"HardwareVersion", &info_arg->hardwareVersion, NULL, test_CK_VERSION},
		{"FirmwareVersion", &info_arg->firmwareVersion, NULL, test_CK_VERSION},
		{"utcTime", &info_arg->utcTime, &utcTime_len, test_CK_CHAR_PTR},
		{NULL, NULL, NULL, NULL}
	};

	r = test_props(info, data, node, prop_map);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	r = test_params(info, data, node, map);
	return r;
}

int
test_CK_SESSION_HANDLE(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_SESSION_HANDLE_PTR session = (CK_SESSION_HANDLE_PTR)ptr;
	int r;
	struct prop_check_map prop_map[] = {
		{"value", session, NULL, test_CK_ULONG_prop},
		{NULL, NULL, NULL, NULL}
	};

	r = test_props(info, data, node, prop_map);
	return r;
}

int
test_CK_MECHANISM_INFO(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_MECHANISM_INFO_PTR mechanism_info = (CK_MECHANISM_INFO_PTR)ptr;
	int r;
	struct prop_check_map prop_map[] = {
		{"MinKeySize", &mechanism_info->ulMinKeySize, NULL, test_CK_ULONG_prop},
		{"MaxKeySize", &mechanism_info->ulMaxKeySize, NULL, test_CK_ULONG_prop},
		{NULL, NULL, NULL, NULL}
	};
	struct param_check_map param_map[] = {
		{"Flags", &mechanism_info->flags, NULL, test_CK_FLAGS},
		{NULL, NULL, NULL, NULL}
	};
	r = test_props(info, data, node, prop_map);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	r = test_params(info, data, node, param_map);
	return r;
}

/* List of structures */
static int
test_CK_SLOT_ID_list(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_SLOT_ID_PTR slot_list = (CK_SLOT_ID_PTR)ptr;
	CK_SLOT_ID expected_slot = 0;
	CK_BBOOL found = CK_FALSE;
	int r = PKCS11TEST_SUCCESS;

	/* get value from node - it is direct value or try to find the stored one */
	r = parse_CK_ULONG(info, data, node, &expected_slot, NULL);
	if (r == PKCS11TEST_DATA_NOT_FOUND) { /* not stored yet */
		/* Just store and do not test returned value */
		CK_ULONG index = 0;
		xmlChar *value = xmlGetProp(node, (const xmlChar*)"value");
		struct internal_data *new_data = calloc(1, sizeof(struct internal_data));
		strcpy(new_data->identifier, (char *)value);
		internal_data_add(data, new_data);
		new_data->data = malloc(sizeof(CK_ULONG));
		extract_index((char *)value, &index);

		if (index >= *length) {
			error_log("Too short slot ID list: expected at least %lu, got %lu.", index + 1, *length);
			return PKCS11TEST_SUCCESS;
		}
		*((CK_ULONG_PTR)(new_data)->data) = slot_list[index];
		return PKCS11TEST_SUCCESS;
	}
	/* go over slot ID list assure there is some item with that value only once */
	for (CK_ULONG i = 0; i < *length; i++) {
		if (slot_list[i] == expected_slot && found == CK_FALSE) {
			found = CK_TRUE;
			log("Slot ID found");
		} else if (slot_list[i] == expected_slot && found == CK_TRUE) {
			error_log("Slot ID %lu found more times", expected_slot);
		}
	}
	if (found == CK_FALSE) {
		error_log("Slot ID %lu not found", expected_slot);
	}
	return r;
}

int
test_CK_SLOT_ID_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	int r;
	struct prop_check_map prop_map[] = {
		{"length", length, NULL, test_CK_ULONG_prop},
		{NULL, NULL, NULL, NULL}
	};
	CK_SLOT_ID_PTR slot_id_list = (CK_SLOT_ID_PTR)ptr;
	struct param_check_map map[] = {
		{"SlotID", slot_id_list, length, test_CK_SLOT_ID_list},
		{NULL, NULL, NULL, NULL}
	};
	r = test_props(info, data, node, prop_map);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	r = test_params(info, data, node, map);
	return r;
}

static int
test_CK_OBJECT_HANDLE_list(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_OBJECT_HANDLE_PTR object_list = (CK_MECHANISM_TYPE_PTR)ptr;
	CK_OBJECT_HANDLE expected_object = 0;
	CK_BBOOL found = CK_FALSE;
	int r = PKCS11TEST_SUCCESS;

	/* get value from node - it is direct value or try to find the stored one */
	r = parse_CK_ULONG(info, data, node, &expected_object, NULL);
	if (r == PKCS11TEST_DATA_NOT_FOUND) { /* not stored yet */
		/* Just store and do not test returned value */
		CK_ULONG index = 0;
		xmlChar *value = xmlGetProp(node, (const xmlChar*)"value");
		extract_index((char *)value, &index);
		if (index >= *length) {
			error_log("Too short object list: expected at least %lu, got %lu.", index + 1, *length);
			return PKCS11TEST_SUCCESS;
		}

		struct internal_data *new_data = calloc(1, sizeof(struct internal_data));
		strcpy(new_data->identifier, (char *)value);
		internal_data_add(data, new_data);
		new_data->data = malloc(sizeof(CK_ULONG));
		*((CK_ULONG_PTR)(new_data)->data) = object_list[index];
		return PKCS11TEST_SUCCESS;
	}
	/* go over object list and assure there is some item with that value only once */
	for (CK_ULONG i = 0; i < *length; i++) {
		if (object_list[i] == expected_object && found == CK_FALSE) {
			found = CK_TRUE;
			log("Object found");
		} else if (object_list[i] == expected_object && found == CK_TRUE) {
			error_log("Object %lu found more times", expected_object);
		}
	}
	if (found == CK_FALSE) {
		error_log("Object %lu not found", expected_object);
	}
	return r;
}

int
test_CK_OBJECT_HANDLE_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_OBJECT_HANDLE_PTR object_list = (CK_OBJECT_HANDLE_PTR)ptr;
	int r;
	struct param_check_map map[] = {
		{"Object", object_list, length, test_CK_OBJECT_HANDLE_list},
		{NULL, NULL, NULL, NULL}
	};
	r = test_params(info, data, node, map);
	return r;
}

static int
test_CK_ATTRIBUTE_list(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_ATTRIBUTE_PTR template = (CK_ATTRIBUTE_PTR)ptr;
	CK_ATTRIBUTE expected_attribute = { 0 };
	CK_BBOOL found = CK_FALSE;
	int r;

	// get value from node
	// convert it from value if stored in internal data
	r = parse_CK_ATTRIBUTE(info, data, node, &expected_attribute, NULL);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	// go over attribute list
	// assure there is some item with that value only once
	for (CK_ULONG i = 0; i < *length; i++) {
		CK_ATTRIBUTE_PTR actual_attribute = &template[i];
		if (expected_attribute.type == actual_attribute->type && found == CK_FALSE) {
			/* we've got hit */
			switch (expected_attribute.type) {
				case CKA_CLASS:
					r = test_CK_OBJECT_CLASS(info, data, node, ptr, length);
					break;
				case CKA_KEY_TYPE:
					r = test_CK_KEY_TYPE(info, data, node, ptr, NULL);
					break;
				case CKA_LABEL:
					r = test_CK_CHAR_PTR(info, data, node, ptr, NULL); // TODO length
					break;
				case CKA_TOKEN:
				case CKA_PRIVATE:
				case CKA_EXTRACTABLE:
				case CKA_SENSITIVE:
				case CKA_ENCRYPT:
				case CKA_DECRYPT:
					r = test_CK_BYTE_prop(info, data, node, (const char **)"value", ptr, NULL);
					break;
				case CKA_VALUE_LEN:
					r = test_CK_ULONG_prop(info, data, node, (const char **)"value", ptr, NULL);
					break;
				case CKA_VALUE:
				case CKA_MODULUS:
				case CKA_PUBLIC_EXPONENT:
					*((CK_BYTE_PTR *)ptr) = NULL_PTR;
					r = test_CK_BYTE_PTR(info, data, node, ptr, NULL); // TODO: length
					break;
				default:
					error_log("Attribute type not known");
					break;
			}
			found = CK_TRUE;
			log("Attribute found");
		} else if (expected_attribute.type == actual_attribute->type && found == CK_TRUE) {
			error_log("Attribute of type %lu found more times", expected_attribute.type);
		}
	}
	if (found == CK_FALSE) {
		error_log("Attribute of type %lu not found", expected_attribute.type);
	}
	return r;
}

int
test_CK_ATTRIBUTE_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_ATTRIBUTE_PTR template = (CK_ATTRIBUTE_PTR)ptr;
	int r;
	struct param_check_map map[] = {
		{"Attribute", template, length, test_CK_ATTRIBUTE_list},
		{NULL, NULL, NULL, NULL}
	};
	r = test_params(info, data, node, map);
	return r;
}

static int
test_CK_MECHANISM_TYPE_list(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_MECHANISM_TYPE_PTR mechanism_list = (CK_MECHANISM_TYPE_PTR)ptr;
	CK_MECHANISM_TYPE expected_mechanism = 0;
	CK_BBOOL found = CK_FALSE;
	int r = PKCS11TEST_SUCCESS;

	/* get value from node - it is direct value or try to find the stored one */
	r = parse_CK_ULONG(info, data, node, &expected_mechanism, NULL);
	if (r == PKCS11TEST_DATA_NOT_FOUND) { /* not stored yet */
		/* Just store and do not test returned value */
		CK_ULONG index = 0;
		xmlChar *value = xmlGetProp(node, (const xmlChar*)"value");
		extract_index((char *)value, &index);
		if (index >= *length) {
			error_log("Too short mechanism list: expected at least %lu, got %lu.", index + 1, *length);
			return PKCS11TEST_SUCCESS;
		}

		struct internal_data *new_data = calloc(1, sizeof(struct internal_data));
		strcpy(new_data->identifier, (char *)value);
		internal_data_add(data, new_data);
		new_data->data = malloc(sizeof(CK_ULONG));
		*((CK_ULONG_PTR)(new_data)->data) = mechanism_list[index];
		return PKCS11TEST_SUCCESS;
	}
	/* go over mechanism list and assure there is some item with that value only once */
	for (CK_ULONG i = 0; i < *length; i++) {
		if (mechanism_list[i] == expected_mechanism && found == CK_FALSE) {
			found = CK_TRUE;
			log("Mechanism found");
		} else if (mechanism_list[i] == expected_mechanism && found == CK_TRUE) {
			error_log("Mechanism %lu found more times", expected_mechanism);
		}
	}
	if (found == CK_FALSE) {
		error_log("Mechanism %lu not found", expected_mechanism);
	}
	return r;
}

int
test_CK_MECHANISM_TYPE_PTR(struct test_info *info, struct internal_data **data, xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_MECHANISM_TYPE_PTR mechanism_list = *((CK_MECHANISM_TYPE_PTR *)ptr);
	int r;
	struct param_check_map param_map[] = {
		{"Type", mechanism_list, length, test_CK_MECHANISM_TYPE_list},
		{NULL, NULL, NULL, NULL}
	};
	r = test_params(info, data, node, param_map);
	return r;
}
