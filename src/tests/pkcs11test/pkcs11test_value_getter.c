#include "pkcs11test_value_getter.h"

int
get_CK_BYTE(const char *value, CK_BYTE_PTR result)
{
	unsigned long r;
    if (xmlStrcasecmp((const xmlChar *)value, (const xmlChar *)"true") == 0) {
        *result = CK_TRUE;
    } else if (xmlStrcasecmp((const xmlChar *)value, (const xmlChar *)"false") == 0) {
        result = CK_FALSE;
    } else {
		char *end = NULL;
		r = strtoul(value, &end, 16);
		if (*end != '\0' || r > 0xFF) {
			return PKCS11TEST_INVALID_ARGUMENTS;
		}
		*result = (CK_BYTE)r;
    }
	return PKCS11TEST_SUCCESS;
}

int
get_CK_FLAGS(char *value, CK_FLAGS *result)
{
	char *token;
	char *delimiter = "| ";
	CK_FLAGS flags = 0x0;
	int r;

	token = strtok(value, delimiter);
    
	while (token != NULL) {
		CK_FLAGS new_flag = 0;
		r = lookup_string(FLG_T, token, &new_flag);
		if (r != PKCS11TEST_SUCCESS) {
			return r;
		}
		flags |= new_flag;
		token = strtok(NULL, delimiter);
	}
	*result = flags;
	return PKCS11TEST_SUCCESS;
}

int
get_num_value(char *value, CK_ULONG *result, enum ck_type type)
{
	if (type == INT) {
		unsigned long r;
		char *end = NULL;
		r = strtoul(value, &end, 10);
		if (*end != '\0') {
			return PKCS11TEST_INVALID_ARGUMENTS;
		}
		*result = (CK_ULONG)r;
	} else {
		return lookup_string(type, (const char *) value, result);
	}
	return PKCS11TEST_INVALID_PARAM_NAME;
}

int
get_CK_UTF8CHAR_PTR(char *value, CK_UTF8CHAR_PTR *result, CK_ULONG_PTR length)
{
	if ((*result = calloc(*length, sizeof(CK_UTF8CHAR))) == NULL) {
		return PKCS11TEST_INTERNAL_ERROR;
	}
	memcpy(*result, value, *length);
	return PKCS11TEST_SUCCESS;
}

int
get_CK_CHAR_PTR(char *value, CK_CHAR_PTR *result, CK_ULONG_PTR length)
{
	if ((*result = calloc(*length, sizeof(CK_UTF8CHAR))) == NULL) {
		return PKCS11TEST_INTERNAL_ERROR;
	}
	memcpy(*result, value, *length);
	return PKCS11TEST_SUCCESS;
}

int
get_CK_BYTE_PTR(char *value, CK_BYTE_PTR *result, CK_ULONG_PTR length)
{
	CK_ULONG str_len = strlen((char *)value);
	if ((*((CK_BYTE_PTR *)result) = malloc(str_len / 2)) == NULL) {
		return PKCS11TEST_INTERNAL_ERROR;
	}
	if (sc_hex_to_bin((CK_BYTE_PTR)value, *result, &str_len) != PKCS11TEST_SUCCESS) {
		free(*((CK_BYTE_PTR *)result));
		return PKCS11TEST_INVALID_ARGUMENTS;
	}
	*length = str_len / 2;
	return PKCS11TEST_SUCCESS;
}
