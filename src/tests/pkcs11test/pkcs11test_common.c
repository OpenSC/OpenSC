#include "pkcs11test_common.h"

int
internal_data_init(struct internal_data **list)
{
	if (list == NULL) {
		return PKCS11TEST_INVALID_ARGUMENTS;
	}
	if ((*list = calloc(1, sizeof(struct internal_data))) == NULL) {
		return PKCS11TEST_INTERNAL_ERROR;
	}
	return PKCS11TEST_SUCCESS;
}

int
internal_data_add(struct internal_data **list, struct internal_data *data)
{
	if (list == NULL || *list == NULL || data == NULL) {
		return PKCS11TEST_INVALID_ARGUMENTS;
	}

	data->next = *list;
	*list = data;

	return PKCS11TEST_SUCCESS;
}

int
internal_data_destroy(struct internal_data **list)
{
	if (list == NULL || *list == NULL) {
		return PKCS11TEST_INVALID_ARGUMENTS;
	}
	
	while (*list != NULL) {
		struct internal_data *next = (*list)->next;
		free((*list)->data);
		free(*list);
		*list = next;
	}
	return PKCS11TEST_SUCCESS;
}

struct internal_data *
internal_data_find(struct internal_data *list, char *identifier)
{
	if (list == NULL) {
		return NULL;
	}
	
	while (list != NULL) {
		if (strcmp(list->identifier, identifier) == 0) {
			return list;
		}
		list = list->next;
	}
	return NULL;
}

int
check_pkcs11_root_node(xmlNode *node)
{
	if (node == NULL || node->type != XML_ELEMENT_NODE) {
		return PKCS11TEST_INVALID_ARGUMENTS;
	}
	return strcmp((char *) node->name, "PKCS11") == 0 ? 1 : 0;
}

int
check_pkcs11_function_node(xmlNode *node)
{
	if (node == NULL || node->type != XML_ELEMENT_NODE) {
		return 0;
	}
	int r1 = strncmp((char *) node->name, "C_", 2) == 0;
	int r2 = strlen((char *) node->name) > 2;
	return r1 && r2 ? 1 : 0;
}

int
get_function_stage(xmlNode *node) {
	if (node == NULL || node->type != XML_ELEMENT_NODE) {
		return PKCS11TEST_INVALID_ARGUMENTS;
	}

	if (check_pkcs11_function_node(node) != 1) {
		return PKCS11TEST_INVALID_ARGUMENTS;
	}

	for (struct _xmlAttr *properties = node->properties; properties; properties = properties->next) {
		if (strcmp("rv", (char *) properties->name) == 0)
			return PKCS11TEST_RETURN_FUNC;
	}
	return PKCS11TEST_CALLING_FUNC;
}

xmlNode *
find_child_by_name(xmlNode *parent_node, const xmlChar *name)
{
	xmlNode *node = NULL;
	if (parent_node == NULL || name == NULL) {
		return NULL;
	}
	for (node = parent_node->children; node; node = node->next) {
		if (node->type == XML_ELEMENT_NODE) {
			if (xmlStrcmp(node->name, name) == 0) {
				return node;
			}
		}
	}
	return NULL;
}

int
extract_index(char *str, CK_ULONG *result)
{
	const char *start = strchr(str, '[');
	const char *end = strchr(str, ']');

    if (start && end && end > start) {
        start++;
        *result = strtoul(start, NULL, 10);
    }
    return PKCS11TEST_INVALID_ARGUMENTS;
}

int sc_hex_to_bin(CK_BYTE_PTR in, CK_BYTE_PTR out, CK_ULONG_PTR outlen)
{
	const char *sc_hex_to_bin_separators = " :";
	if (in == NULL || out == NULL || outlen == NULL) {
		return PKCS11TEST_INVALID_ARGUMENTS;
	}

	int byte_needs_nibble = 0;
	int r = PKCS11TEST_SUCCESS;
	size_t left = *outlen;
	CK_BYTE byte = 0;
	while (*in != '\0' && 0 != left) {
		CK_BYTE c = *in++;
		CK_BYTE nibble;
		if      ('0' <= c && c <= '9')
			nibble = c - '0';
		else if ('a' <= c && c <= 'f')
			nibble = c - 'a' + 10;
		else if ('A' <= c && c <= 'F')
			nibble = c - 'A' + 10;
		else {
			if (strchr(sc_hex_to_bin_separators, (int) c)) {
				if (byte_needs_nibble) {
					r = PKCS11TEST_INVALID_ARGUMENTS;
					goto err;
				}
				continue;
			}
			r = PKCS11TEST_INVALID_ARGUMENTS;
			goto err;
		}

		if (byte_needs_nibble) {
			byte |= nibble;
			*out++ = (CK_BYTE) byte;
			left--;
			byte_needs_nibble = 0;
		} else {
			byte  = nibble << 4;
			byte_needs_nibble = 1;
		}
	}

	if (left == *outlen && 1 == byte_needs_nibble && 0 != left) {
		/* no output written so far, but we have a valid nibble in the upper
		 * bits. Allow this special case. */
		*out = (CK_BYTE) byte>>4;
		left--;
		byte_needs_nibble = 0;
	}

	/* for ease of implementation we only accept completely hexed bytes. */
	if (byte_needs_nibble) {
		r = PKCS11TEST_INVALID_ARGUMENTS;
		goto err;
	}

	/* skip all trailing separators to see if we missed something */
	while (*in != '\0') {
		if (NULL == strchr(sc_hex_to_bin_separators, (int) *in))
			break;
		in++;
	}
	if (*in != '\0') {
		r = PKCS11TEST_INTERNAL_ERROR;
		goto err;
	}

err:
	*outlen -= left;
	return r;
}

int sc_bin_to_hex(CK_BYTE_PTR in, CK_ULONG in_len, CK_BYTE_PTR out, CK_ULONG out_len,
				  int in_sep)
{
	if (in == NULL || out == NULL) {
		return PKCS11TEST_INVALID_ARGUMENTS;
	}

	if (in_sep > 0) {
		if (out_len < in_len*3 || out_len < 1)
			return PKCS11TEST_INVALID_ARGUMENTS;
	} else {
		if (out_len < in_len*2 + 1)
			return PKCS11TEST_INVALID_ARGUMENTS;
	}

	const char hex[] = "0123456789abcdef";
	while (in_len) {
		unsigned char value = *in++;
		*out++ = hex[(value >> 4) & 0xF];
		*out++ = hex[ value       & 0xF];
		in_len--;
		if (in_len && in_sep > 0)
			*out++ = (char)in_sep;
	}
	*out = '\0';

	return PKCS11TEST_SUCCESS;
}
