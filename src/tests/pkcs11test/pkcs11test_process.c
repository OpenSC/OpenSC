#include "pkcs11test_process.h"
#include "pkcs11test_common.h"
#include "pkcs11test_func.h"

int
pkcs11test_run(xmlDoc *test_doc, struct test_info *info)
{
	int retval = PKCS11TEST_SUCCESS;
	xmlNode *root = NULL;
	struct internal_data *data = NULL;
	xmlNode *calling_func = NULL;
	xmlNode *return_func = NULL;

	if (test_doc == NULL || info == NULL) {
		return PKCS11TEST_INVALID_ARGUMENTS;
	}

	if ((retval = internal_data_init(&data)) != PKCS11TEST_SUCCESS) {
		error_log("Internal error when allocating internal data structures");
		goto end;
	}

	/* Get root of XML structure */
	root = xmlDocGetRootElement(test_doc);
	if (check_pkcs11_root_node(root) != 1) {
		error_log("XML file does not contain correct root node");
		retval = PKCS11TEST_XML_ERROR;
		goto end;
	}

	if (info->pin != NULL) {
		/* Store PIN into internal data if provided */
		struct internal_data *pin_data = calloc(1, sizeof(struct internal_data));
		strcpy(pin_data->identifier, "${Pin}");
		internal_data_add(&data, pin_data);
		pin_data->data = strdup((char *)info->pin);
		pin_data->length = info->pin_length;
	}

	for (xmlNode *node = root->children; node; node = node->next) {
		int type;
		process_func func;

		if (node->type != XML_ELEMENT_NODE)
			continue;
		type = get_function_stage(node);
		if (type == PKCS11TEST_CALLING_FUNC) {
			calling_func = node;
		} else if (type == PKCS11TEST_RETURN_FUNC) {
			return_func = node;
			if (calling_func == NULL || xmlStrcmp(calling_func->name, return_func->name) != 0) {
				error_log("Not matching calling (%s) and return (%s) function calls", calling_func->name, return_func->name);
				continue;
			}

			if ((func = get_pkcs11_function((char *) node->name)) == NULL) {
				error_log("Unsupported function %s", node->name);
				continue;
			}
			func(calling_func, return_func, &data, info);
		} else {
			/* On this level, non-function node is not allowed */
			error_log("\"%s\" is not PKCS#11 function", node->name);
			continue;
		}
	}
end:
	internal_data_destroy(&data);
	return retval;
}
