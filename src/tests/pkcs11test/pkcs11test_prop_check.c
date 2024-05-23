#include "pkcs11test_prop_check.h"

int
test_props(struct test_info *info, struct internal_data **data, xmlNode *node, struct prop_check_map map[])
{
	xmlChar *value = NULL;
	int r = PKCS11TEST_SUCCESS;
	for (int i = 0; map[i].name != NULL; i++) { // go over all specified parameters in array
		if ((value = xmlGetProp(node, (const xmlChar*)(map[i].name))) != NULL) { // find corresponding property
			// get parser
			prop_check_func func = map[i].check_func;
			if (func != NULL) {
				log("\t\t\t\"%s\": Checking property against actual return value.", map[i].name);
				func(info, data, node, &map[i].name, map[i].ptr, map[i].length);
				if (r != PKCS11TEST_SUCCESS) {
					return r;
				}
			}
		}
	}
	return r;
}

int
test_CK_BYTE_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	xmlChar *value = NULL;
	CK_BYTE actual = *((CK_ULONG_PTR) ptr);
	int r;

	value = xmlGetProp(node, (const xmlChar*)*name);
	if (value == NULL) {
		return PKCS11TEST_PARAM_ABSENT;
	}

	if (value[0] == '$') {
		/* Find symbol among stored ones*/
		struct internal_data *data_length = internal_data_find(*data, (char *)value);
		if (data_length == NULL) {
			/* Not found, store it into internal data */
			if ((data_length = calloc(1, sizeof(struct internal_data))) == NULL
					|| (data_length->data = malloc(sizeof(CK_ULONG))) == NULL) {
				free(data_length);
				return PKCS11TEST_INTERNAL_ERROR;
			}
			strcpy(data_length->identifier, (char *)value);
			internal_data_add(data, data_length);
		} else {
			/* Value found, check against actual value*/
			check_CK_BYTE(*((CK_BYTE_PTR)data_length->data), actual);
		}
		*((CK_BYTE_PTR)(*data)->data) = actual;
	} else {
		/* Check length directly against actual byte */
		CK_BYTE expected;
		if ((r = get_CK_BYTE((char *)value, &expected)) != PKCS11TEST_SUCCESS) {
			return r;
		}
		check_CK_BYTE(expected, actual);
	}
	return PKCS11TEST_SUCCESS;
}

static int
test_num_value(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length, enum ck_type type)
{
	xmlChar *value = NULL;
	CK_ULONG actual = *((CK_ULONG_PTR) ptr);
	int r;

	value = xmlGetProp(node, (const xmlChar*)*name);
	if (value == NULL) {
		return PKCS11TEST_PARAM_ABSENT;
	}

	if (value[0] == '$') {
		/* Find symbol among stored ones*/
		struct internal_data *stored_data = internal_data_find(*data, (char *)value);
		if (stored_data == NULL) {
			/* Not found, store it into internal data */
			log("\t\t\t\t\tStoring %s = %lu.", (char *)value, actual);
			if ((stored_data = calloc(1, sizeof(struct internal_data))) == NULL
					|| (stored_data->data = malloc(sizeof(CK_ULONG))) == NULL) {
				free(stored_data);
				return PKCS11TEST_INTERNAL_ERROR;
			}
			strcpy(stored_data->identifier, (char *)value);
			internal_data_add(data, stored_data);
		} else {
			/* Value found, check against actual value */
			log("\t\t\t\t\tFound stored %s = %lu.", (char *)value, actual);
			check_num_value(*((CK_ULONG_PTR)stored_data->data), actual, type);
		}
		*((CK_ULONG_PTR)(*data)->data) = actual;
	} else {
		/* Check length directly against actual length */
		CK_ULONG expected;
		if ((r = get_num_value((char *)value, &expected, type)) != PKCS11TEST_SUCCESS) {
			return r;
		}
		check_num_value(expected, actual, type);
	}
	return PKCS11TEST_SUCCESS;
}

int
test_CK_ULONG_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	return test_num_value(info, data, node, name, ptr, length, INT);
}

int
test_CK_RV_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	return test_num_value(info, data, node, name, ptr, length, RV_T);
}

int
test_CK_FLAGS_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	return test_num_value(info, data, node, name, ptr, length, FLG_T);
}

int
test_CK_OBJECT_CLASS_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	return test_num_value(info, data, node, name, ptr, length, OBJ_T);
}

int
test_CK_KEY_TYPE_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	return test_num_value(info, data, node, name, ptr, length, KEY_T);
}

int
test_CK_UTF8CHAR_PTR_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	xmlChar *value = NULL;
	CK_UTF8CHAR_PTR actual = (CK_UTF8CHAR_PTR) ptr;
	int r;

	value = xmlGetProp(node, (const xmlChar*)*name);
	if (value == NULL) {
		return PKCS11TEST_PARAM_ABSENT;
	}

	if (value[0] == '$') {
		/* Find symbol among stored ones*/
		struct internal_data *stored_data = internal_data_find(*data, (char *)value);
		if (stored_data == NULL) {
			/* Not found, store it into internal data */
			log("\t\t\t\t\tStoring %s.", (char *)value);
			if ((stored_data = calloc(1, sizeof(struct internal_data))) == NULL
					|| (stored_data->data = malloc((*length) * sizeof(CK_UTF8CHAR))) == NULL) {
				free(stored_data);
				return PKCS11TEST_INTERNAL_ERROR;
			}
			strcpy(stored_data->identifier, (char *)value);
			internal_data_add(data, stored_data);
		} else {
			/* Value found, check against actual value*/
			log("\t\t\t\t\tFound stored %s.", (char *)value);
			check_memory(stored_data->data, actual, *length);
		}
		stored_data->data = actual;
		stored_data->length = *length;
	} else {
		/* Check length directly against actual byte */
		CK_UTF8CHAR_PTR expected;
		if ((r = get_CK_UTF8CHAR_PTR((char *)value, &expected, length)) != PKCS11TEST_SUCCESS) {
			return r;
		}
		check_memory(expected, actual, *length);
	}
	return PKCS11TEST_SUCCESS;
}

int
test_CK_CHAR_PTR_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	xmlChar *value = NULL;
	CK_CHAR_PTR actual = (CK_CHAR_PTR) ptr;
	int r;

	value = xmlGetProp(node, (const xmlChar*)*name);
	if (value == NULL) {
		return PKCS11TEST_PARAM_ABSENT;
	}

	if (value[0] == '$') {
		/* Find symbol among stored ones*/
		struct internal_data *stored_data = internal_data_find(*data, (char *)value);
		if (stored_data == NULL) {
			/* Not found, store it into internal data */
			log("\t\t\t\t\tStoring %s.", (char *)value);
			if ((stored_data = calloc(1, sizeof(struct internal_data))) == NULL
					|| (stored_data->data = malloc((*length) * sizeof(CK_CHAR))) == NULL) {
				free(stored_data);
			}
			strcpy(stored_data->identifier, (char *)value);
			internal_data_add(data, stored_data);
		} else {
			/* Value found, check against actual value*/
			log("\t\t\t\t\tFound stored %s.", (char *)value);
			check_memory(stored_data->data, actual, *length);
		}
		stored_data->data = actual;
		stored_data->length = *length;
	} else {
		/* Check length directly against actual byte */
		CK_CHAR_PTR expected;
		if ((r = get_CK_CHAR_PTR((char *)value, &expected, length)) != PKCS11TEST_SUCCESS) {
			return r;
		}
		check_memory(expected, actual, *length);
	}
	return PKCS11TEST_SUCCESS;
}

int
test_CK_BYTE_PTR_prop(struct test_info *info, struct internal_data **data, xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	xmlChar *value = NULL;
	CK_BYTE_PTR actual = *((CK_BYTE_PTR *) ptr);
	int r;

	value = xmlGetProp(node, (const xmlChar*)*name);
	if (value == NULL) {
		return PKCS11TEST_PARAM_ABSENT;
	}

	if (value[0] == '$') {
		/* Find symbol among stored ones*/
		struct internal_data *stored_data = internal_data_find(*data, (char *)value);
		if (stored_data == NULL) {
			/* Not found, store it into internal data */
			log("\t\t\t\t\tStoring %s.", (char *)value);
			if ((stored_data = calloc(1, sizeof(struct internal_data))) == NULL
					|| (stored_data->data = malloc((*length) * sizeof(CK_BYTE))) == NULL) {
				free(stored_data);
				return PKCS11TEST_INTERNAL_ERROR;
			}
			strcpy(stored_data->identifier, (char *)value);
			internal_data_add(data, stored_data);
		} else {
			/* Value found, check against actual value*/
			log("\t\t\t\t\tFound stored %s.", (char *)value);
			check_memory(stored_data->data, actual, *length);
		}
		stored_data->data = actual;
		stored_data->length = *length;
	} else {
		/* Check length directly against actual byte */
		CK_BYTE_PTR expected;
		if ((r = get_CK_BYTE_PTR((char *)value, &expected, length)) != PKCS11TEST_SUCCESS) {
			return r;
		}
		check_memory(expected, actual, *length);
	}
	return PKCS11TEST_SUCCESS;
}
