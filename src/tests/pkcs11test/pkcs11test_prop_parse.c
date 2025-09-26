/**
 * Wrappers around string to int lookup tables and low-level type parsers
 * get_*() functions - extract value from string
 * parse_*() functions - parse value/structure out of XML node
 */

#include "pkcs11test_prop_parse.h"

int
parse_props(struct test_info *info, struct internal_data **data, xmlNode *node,
		struct prop_parse_map map[])
{
	int r = PKCS11TEST_SUCCESS;
	xmlChar *value = NULL;
	for (int i = 0; map[i].name != NULL; i++) { // go over all specified parameters in array
		if ((value = xmlGetProp(node, (const xmlChar*)(map[i].name))) != NULL) { // find corresponding property
			// get parser
			if (map[i].parser_func != NULL) {
				log("\t\t\t\"%s\": Parsing property.", map[i].name);
				r = map[i].parser_func(info, data, node, &map[i].name, map[i].ptr, map[i].length);
				if (r != PKCS11TEST_SUCCESS) {
					return r;
				}
			}
		}
	}
	return r;
}

/* parser from properties*/

int
parse_CK_RV(xmlNode *node, CK_RV *rv)
{
	xmlChar *value = NULL;
	if ((value = xmlGetProp(node, (const xmlChar*)("rv"))) == NULL) {
		return PKCS11TEST_PROP_ABSENT;
	}
	return get_num_value((char *)value, rv, RV_T);
}

int
parse_CK_BYTE_prop(struct test_info *info, struct internal_data **data,
		xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	int r = PKCS11TEST_SUCCESS;
	xmlChar *value = NULL;
	CK_BYTE rv = 0x0;
	if ((value = xmlGetProp(node, (const xmlChar*)(*name))) == NULL) {
		return PKCS11TEST_PROP_ABSENT;
	}
	r = get_CK_BYTE((const char *)value, &rv);
	*((CK_BYTE *)ptr) = rv;
	return r;
}

static int
parse_num_value(struct test_info *info, struct internal_data **data,
		xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length, enum ck_type type)
{
	int r = PKCS11TEST_SUCCESS;
	xmlChar *value = NULL;
	if ((value = xmlGetProp(node, (const xmlChar*)(*name))) == NULL) {
		return PKCS11TEST_PROP_ABSENT;
	}
	if (value == NULL) {
		/* 1. Value not present */
		*((CK_ULONG *)ptr) = 0;
	} else {
		/* 2. Value present, either directly or stored in internal data */
		if (value[0] == '$') {
			struct internal_data *stored_data = internal_data_find(*data, (char *)value);
			if (stored_data == NULL) {
				error_log("Stored %s not found.", (char *) value);
				return PKCS11TEST_DATA_NOT_FOUND;
			}
			*((CK_ULONG *)ptr) = *((CK_ULONG_PTR)stored_data->data);
		} else {
			r = get_num_value((char *)value, (CK_ULONG_PTR)ptr, type);
		}
	}
	return r;
}

int
parse_CK_ULONG_prop(struct test_info *info, struct internal_data **data,
		xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	return parse_num_value(info, data, node, name, ptr, length, INT);
}

int
parse_CK_OBJECT_CLASS_prop(struct test_info *info, struct internal_data **data,
		xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	return parse_num_value(info, data, node, name, ptr, length, OBJ_T);
}

int
parse_CK_KEY_TYPE_prop(struct test_info *info, struct internal_data **data,
		xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	return parse_num_value(info, data, node, name, ptr, length, KEY_T);
}

int
parse_CK_USER_TYPE_prop(struct test_info *info, struct internal_data **data,
		xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	return parse_num_value(info, data, node, name, ptr, length, USR_T);
}

int
parse_CK_FLAGS_prop(struct test_info *info, struct internal_data **data,
		xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	return parse_num_value(info, data, node, name, ptr, length, FLG_T);
}

int
parse_CK_ATTRIBUTE_TYPE_prop(struct test_info *info, struct internal_data **data,
		xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	return parse_num_value(info, data, node, name, ptr, length, ATR_T);
}

int
parse_CK_MECHANISM_TYPE_prop(struct test_info *info, struct internal_data **data,
		xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	return parse_num_value(info, data, node, name, ptr, length, MEC_T);
}

int
parse_CK_UTF8CHAR_PTR_prop(struct test_info *info, struct internal_data **data,
		xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	int r = PKCS11TEST_SUCCESS;
	xmlChar *value = NULL;
	if ((value = xmlGetProp(node, (const xmlChar*)(*name))) == NULL) {
		return PKCS11TEST_PROP_ABSENT;
	}
	if (value[0] == '$') {
		struct internal_data *slot_id_data = internal_data_find(*data, (char *)value);
		if (slot_id_data == NULL) {
			error_log("No value %s provided or stored.", (char *)value);
			return PKCS11TEST_DATA_NOT_FOUND;
		}
		r = get_CK_UTF8CHAR_PTR((char *)slot_id_data->data, ptr, &slot_id_data->length);
		*length = slot_id_data->length;
	} else {
		r = get_CK_UTF8CHAR_PTR((char *)value, ptr, length);
	}
	return r; 
}

int
parse_CK_CHAR_PTR_prop(struct test_info *info, struct internal_data **data,
		xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	int r = PKCS11TEST_SUCCESS;
	xmlChar *value = NULL;
	if ((value = xmlGetProp(node, (const xmlChar*)(*name))) == NULL) {
		return PKCS11TEST_PROP_ABSENT;
	}
	if (value[0] == '$') {
		struct internal_data *slot_id_data = internal_data_find(*data, (char *)value);
		if (slot_id_data == NULL) {
			error_log("No value %s provided or stored.", (char *)value);
			return PKCS11TEST_DATA_NOT_FOUND;
		}
		r = get_CK_CHAR_PTR((char *)slot_id_data->data, ptr, &slot_id_data->length);
		*length = slot_id_data->length;
	} else {
		r = get_CK_CHAR_PTR((char *)value, ptr, length);
	}
	return r; 
}

int
parse_CK_BYTE_PTR_prop(struct test_info *info, struct internal_data **data,
		xmlNode *node, const char **name, CK_VOID_PTR ptr, CK_ULONG_PTR length)
{
	int r = PKCS11TEST_SUCCESS;
	xmlChar *value = NULL;
	if ((value = xmlGetProp(node, (const xmlChar*)(*name))) == NULL) {
		return PKCS11TEST_PROP_ABSENT;
	}
	if (value[0] == '$') {
		struct internal_data *slot_id_data = internal_data_find(*data, (char *)value);
		if (slot_id_data == NULL) {
			error_log("No value %s provided or stored.", (char *)value);
			return PKCS11TEST_DATA_NOT_FOUND;
		}
		r = get_CK_BYTE_PTR((char *)slot_id_data->data, ptr, &slot_id_data->length);
		*length = slot_id_data->length;
	} else {
		r = get_CK_BYTE_PTR((char *)value, ptr, length);
	}
	return r; 
}
