#include "pkcs11test_params_parse.h"

// TODO: Fix for more children
int
parse_params(struct test_info *info, struct internal_data **data,
		xmlNode *parent_node, struct param_parse_map map[])
{
	xmlNode *node = NULL;
	int r;
	if (parent_node == NULL || data == NULL || map == NULL) {
		return PKCS11TEST_INVALID_ARGUMENTS;
	}
	for (node = parent_node->children; node; node = node->next) { // go over all nodes
		if (node->type == XML_ELEMENT_NODE) {
			for (int i = 0; map[i].name != NULL; i++) { // go over all specified parameters in array
				if (strcmp((char *)node->name, map[i].name) == 0) {
					// get parser
					parser_func func = map[i].parser_func;
					if (func != NULL) {
						log("\t%s: Parsing param node.", (char *)node->name);
						// fill parameter pointers
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

/* Non-nested structures types*/
int
parse_CK_BBOOL(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_BBOOL value = 0;
	int r;
	struct prop_parse_map prop_map[] = {
		{"value", &value, NULL, parse_CK_BYTE_prop},
		{NULL, NULL, NULL, NULL}
	};
	r = parse_props(info, data, node, prop_map);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	*((CK_BBOOL *)ptr) = value;
	return PKCS11TEST_SUCCESS; 
}

int
parse_CK_ULONG(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_ULONG value = 0;
	int r = PKCS11TEST_SUCCESS;
	struct prop_parse_map prop_map[] = {
		{"value", &value, NULL, parse_CK_ULONG_prop},
		{NULL, NULL, NULL, NULL}
	};
	r = parse_props(info, data, node, prop_map);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	*((CK_ULONG *)ptr) = value;
	return r;
}

int
parse_CK_FLAGS(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_FLAGS value = 0;
	int r;
	struct prop_parse_map prop_map[] = {
		{"value", &value, NULL, parse_CK_FLAGS_prop},
		{NULL, NULL, NULL, NULL}
	};
	r = parse_props(info, data, node, prop_map);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	*((CK_FLAGS *)ptr) = value;
	return r; 
}

int
parse_CK_UTF8CHAR_PTR(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_UTF8CHAR_PTR value = NULL;
	int r;
	struct prop_parse_map prop_map[] = {
		{"value", &value, length, parse_CK_UTF8CHAR_PTR_prop},
		{NULL, NULL, NULL, NULL}
	};
	r = parse_props(info, data, node, prop_map);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	*((CK_UTF8CHAR_PTR *)ptr) = value;
	return r; 
}

int
parse_CK_CHAR_PTR(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_CHAR_PTR value = NULL_PTR;
	CK_ULONG value_len = 0;
	int r;
	struct prop_parse_map prop_map[] = {
		{"value", &value, &value_len, parse_CK_CHAR_PTR_prop},
		{"length", &value_len, NULL, parse_CK_ULONG_prop},
		{NULL, NULL, NULL, NULL}
	};
	r = parse_props(info, data, node, prop_map);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	if (value != NULL_PTR) {
		*((CK_CHAR_PTR *)ptr) = value;
	} else if (value_len > 0) {
		*((CK_CHAR_PTR *)ptr) = malloc(value_len * sizeof(char));
	}
	*length = value_len;
	return r; 
}

int
parse_CK_BYTE_PTR(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_BYTE_PTR value = NULL_PTR;
	CK_ULONG value_len = 0;
	int r;
	struct prop_parse_map prop_map[] = {
		{"value", &value, &value_len, parse_CK_BYTE_PTR_prop},
		{"length", &value_len, NULL, parse_CK_ULONG_prop},
		{NULL, NULL, NULL, NULL}
	};
	r = parse_props(info, data, node, prop_map);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	if (value != NULL_PTR) {
		*((CK_BYTE_PTR *)ptr) = value;
	} else if (value_len > 0) {
		if ((*((CK_BYTE_PTR *)ptr) = malloc(value_len * sizeof(char))) == NULL) {
			return PKCS11TEST_INTERNAL_ERROR;
		}
	}
	*length = value_len;
	return r; 
}

int
parse_CK_USER_TYPE(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_USER_TYPE value = 0;
	int r;
	struct prop_parse_map prop_map[] = {
		{"value", &value, NULL, parse_CK_USER_TYPE_prop},
		{NULL, NULL, NULL, NULL}
	};
	r = parse_props(info, data, node, prop_map);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	*((CK_USER_TYPE *)ptr) = value;
	return r; 
}

int
parse_CK_SESSION_HANDLE(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_SESSION_HANDLE session = 0;
	int r;
	struct prop_parse_map prop_map[] = {
		{"value", &session, NULL, parse_CK_ULONG_prop},
		{NULL, NULL, NULL, NULL}
	};
	r = parse_props(info, data, node, prop_map);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	return r; 
}

int
parse_CK_MECHANISM_TYPE(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_MECHANISM_TYPE value = 0;
	int r;
	struct prop_parse_map prop_map[] = {
		{"value", &value, NULL, parse_CK_MECHANISM_TYPE_prop},
		{NULL, NULL, NULL, NULL}
	};
	r = parse_props(info, data, node, prop_map);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	*((CK_MECHANISM_TYPE *)ptr) = value;
	return r; 
}

int
parse_CK_ATTRIBUTE(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_ATTRIBUTE_PTR attribute = (CK_ATTRIBUTE_PTR)ptr;
	CK_ATTRIBUTE_TYPE type = 0;
	CK_VOID_PTR value = NULL_PTR;
	CK_ULONG value_length = 0;
	CK_ULONG type_length = 0;
	const char *name = "value";
	int r;

	struct prop_parse_map prop_map[] = {
		{"length", &value_length, NULL, parse_CK_ULONG_prop},
		{"type", &type, NULL, parse_CK_ATTRIBUTE_TYPE_prop},
		{NULL, NULL, NULL, NULL}
	};
	r = parse_props(info, data, node, prop_map);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	/* Currently specified types among official test cases */
	switch (type) {
		case CKA_CLASS:
			r = parse_CK_OBJECT_CLASS_prop(info, data, node, &name, ptr, NULL);
			break;
		case CKA_KEY_TYPE:
			r = parse_CK_KEY_TYPE_prop(info, data, node, &name, ptr, NULL);
			break;
		case CKA_LABEL:
			r = parse_CK_UTF8CHAR_PTR_prop(info, data, node, &name, ptr, &type_length);
			break;
		case CKA_TOKEN:
		case CKA_PRIVATE:
		case CKA_EXTRACTABLE:
		case CKA_SENSITIVE:
		case CKA_ENCRYPT:
		case CKA_DECRYPT:
			r = parse_CK_BYTE_prop(info, data, node, &name, ptr, NULL);
			break;
		case CKA_VALUE_LEN:
			r = parse_CK_ULONG_prop(info, data, node, &name, ptr, NULL);
			break;
		case CKA_MODULUS:
		case CKA_PUBLIC_EXPONENT:
			*((CK_BYTE_PTR *)ptr) = NULL_PTR;
			r = parse_CK_BYTE_PTR_prop(info, data, node, &name, ptr, &type_length);
			break;
		default:
			error_log("Attribute type not known");
			break;
	}
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	attribute->type = type;
	attribute->ulValueLen = value_length;
	if (value_length == 0) {
		/* Value will not be allocated, but might be assigned directly or let be NULL*/
		attribute->pValue = value;
	} else {
		/* length was specified, value is to be allocated for further filling */
		if ((attribute->pValue = calloc(value_length, sizeof(char))) == NULL) {
			return PKCS11TEST_INTERNAL_ERROR;
		}
	}
	return r;
}

/* Nested structures types*/
int
parse_CK_C_INITIALIZE_ARGS(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	if (node == NULL || data == NULL || ptr == NULL_PTR) {
		return PKCS11TEST_INVALID_ARGUMENTS;
	}
	return PKCS11TEST_SUCCESS;
}

int
parse_CK_VERSION(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_BYTE major = 0, minor = 0;
	int r;
	struct prop_parse_map prop_map[] = {
		{"minor", &minor, NULL, parse_CK_BYTE_prop},
		{"major", &major, NULL, parse_CK_BYTE_prop},
		{NULL, NULL, NULL, NULL}
	};

	r = parse_props(info, data, node, prop_map);
	return r; 
}

/* Parsing list ob objects */
int
parse_CK_SLOT_ID_PTR(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_SLOT_ID_PTR list = NULL;
	CK_ULONG list_length = 0;
	int r;

	struct prop_parse_map prop_map[] = {
		{"length", &list_length, NULL, parse_CK_ULONG_prop},
		{NULL, NULL, NULL, NULL}
	};

	r = parse_props(info, data, node, prop_map);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	if (list_length != 0) {
		*length = list_length;
		if (list_length == 0) {
			log("Empty CK_SLOT_ID list");
			return PKCS11TEST_SUCCESS; 
		}
		if ((list = calloc(list_length, sizeof(CK_SLOT_ID))) == NULL) {
			return PKCS11TEST_INTERNAL_ERROR;
		}
		*((CK_SLOT_ID_PTR *)ptr) = list;
	} else {
		/* Parse list of slot IDs */
	}

	return r;
}

static int
parse_CK_ATTRIBUTE_list(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_ATTRIBUTE_PTR attribute_list = *((CK_ATTRIBUTE_PTR *) ptr);
	int r;

	if (*length == 0) {
		/* List is empty, allocated new list */
		if ((attribute_list = calloc(1, sizeof(CK_ATTRIBUTE))) == NULL) {
			return PKCS11TEST_INTERNAL_ERROR;
		}
	} else {
		/* list exists, add to the list*/
		CK_ATTRIBUTE_PTR tmp = realloc(attribute_list, (*length + 1)* sizeof(CK_ATTRIBUTE));
		attribute_list = tmp;
	}
	/* parse from node to the list */
	r = parse_CK_ATTRIBUTE(info, data, node, attribute_list + (*length) * sizeof(CK_ATTRIBUTE), NULL);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	*length += 1;
	return r;
}

int
parse_CK_ATTRIBUTE_PTR(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_ATTRIBUTE_PTR template = NULL_PTR;
	CK_ULONG template_length = 0;
	int r;

	struct prop_parse_map prop_map[] = {
		{"length", &template_length, NULL, parse_CK_ULONG_prop},
		{NULL, NULL, NULL, NULL}
	};

	struct param_parse_map param_map[] = {
		{"Attribute", &template, &template_length, parse_CK_ATTRIBUTE_list},
		{NULL, NULL, NULL, NULL}
	};
	r = parse_props(info, data, node, prop_map);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}

	if (template_length != 0) {
		*length = template_length;
		if (template_length == 0) {
			log("Empty CK_ATTRIBUTE list");
			return PKCS11TEST_SUCCESS; 
		}
		template = calloc(template_length, sizeof(CK_ATTRIBUTE_PTR));
		*((CK_ATTRIBUTE_PTR *)ptr) = template;
	} else {
		r = parse_params(info, data, node, param_map);
	}
	return r;
}

int
parse_CK_OBJECT_HANDLE_PTR(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_OBJECT_HANDLE_PTR list = NULL;
	CK_ULONG list_length = 0;
	int r;

	struct prop_parse_map prop_map[] = {
		{"length", &list_length, NULL, parse_CK_ULONG_prop},
		{NULL, NULL, NULL, NULL}
	};

	r = parse_props(info, data, node, prop_map);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	if (list_length != 0) {
		*length = list_length;
		if (list_length == 0) {
			log("Empty CK_OBJECT_HANDLE list");
			return PKCS11TEST_SUCCESS; 
		}
		list = calloc(list_length, sizeof(CK_OBJECT_HANDLE));
		*((CK_OBJECT_HANDLE_PTR *)ptr) = list;
	} else {
		/* Parse list of object handles */
	}

	return PKCS11TEST_SUCCESS;
}

int
parse_CK_MECHANISM(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_MECHANISM_PTR mechanism = (CK_MECHANISM_PTR) ptr;
	int r;
	struct param_parse_map param_map[] = {
		{"Type", &mechanism->mechanism, NULL, parse_CK_MECHANISM_TYPE},
		{"Parameter", &mechanism->pParameter, &mechanism->ulParameterLen, NULL}, // TODO: Process mechanism parameters
		{NULL, NULL, NULL, NULL}
	};
	r = parse_params(info, data, node, param_map);
	return r;
}


static int
parse_CK_MECHANISM_TYPE_list(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_MECHANISM_TYPE_PTR mechanism_list = *((CK_MECHANISM_TYPE_PTR *) ptr);
	int r;
	if (*length == 0) {
		/* List is empty, allocated new list */
		mechanism_list = calloc(1, sizeof(CK_MECHANISM_TYPE));
	} else {
		/* list exists, add to the list*/
		CK_MECHANISM_TYPE_PTR tmp = realloc(mechanism_list, (*length + 1)* sizeof(CK_MECHANISM_TYPE));
		mechanism_list = tmp;
	}
	/* parse from node to the list */
	r = parse_CK_MECHANISM_TYPE(info, data, node, &(mechanism_list[*length]), NULL);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}
	*length += 1;
	return r;
}

int
parse_CK_MECHANISM_TYPE_PTR(struct test_info *info, struct internal_data **data,
		xmlNode *node, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	CK_MECHANISM_TYPE_PTR mechanism_list = NULL_PTR;
	CK_ULONG mechanism_list_len = 0;
	int r;

	struct prop_parse_map prop_map[] = {
		{"length", &mechanism_list_len, NULL, parse_CK_ULONG_prop},
		{NULL, NULL, NULL, NULL}
	};
	/* For now, there is no need for parsing the list */
	struct param_parse_map param_map[] = {
		{"Type", &mechanism_list, &mechanism_list_len, parse_CK_MECHANISM_TYPE_list},
		{NULL, NULL, NULL, NULL}
	};

	r = parse_props(info, data, node, prop_map);
	if (r != PKCS11TEST_SUCCESS && r != PKCS11TEST_DATA_NOT_FOUND) {
		return r;
	}

	if (mechanism_list_len != 0) { /* if length is specified allocated enough space and leave*/
		*length = mechanism_list_len;
		if (mechanism_list_len == 0) {
			log("Empty CK_OBJECT_HANDLE list");
			return PKCS11TEST_SUCCESS; 
		}
		mechanism_list = calloc(mechanism_list_len, sizeof(CK_OBJECT_HANDLE));
		*((CK_MECHANISM_TYPE_PTR *)ptr) = mechanism_list;
	} else {
		r = parse_params(info, data, node, param_map);
	}
	return r;
}
