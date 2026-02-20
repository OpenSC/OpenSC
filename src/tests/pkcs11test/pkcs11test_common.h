#ifndef PKCS11TEST_COMMON_H
#define PKCS11TEST_COMMON_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "pkcs11/pkcs11.h"
#include "pkcs11test_types.h"

int internal_data_init(struct internal_data **list);
int internal_data_add(struct internal_data **list, struct internal_data *data);
int internal_data_add_ptr(struct internal_data **list, void *ptr);
int internal_data_destroy(struct internal_data **list);
struct internal_data * internal_data_find(struct internal_data *list, char *identifier);

/**
 * Check that given node is root node of PKCS#11 XML test case
 * 
 * @param node  XML node to be checked
 * @return 1 if it is root node, 0 otherwise
 */
int check_pkcs11_root_node(xmlNode *node);

/**
 * Check that given node is node of existing PKCS#11 function
 * 
 * @param node  XML node to be checked
 * @return 1 if it is function node, 0 otherwise
 */
int check_pkcs11_function_node(xmlNode *node);

/**
 * Check whether node represents function call or function return value.
 * 
 * @param node  XML node to be checked
 * @return PKCS11TEST_CALLING_FUNC if function call, if return call
 */
int get_function_stage(xmlNode *node);

xmlNode *find_child_by_name(xmlNode *parent_node, const xmlChar *name);
int extract_index(char *str, CK_ULONG *result);
int sc_hex_to_bin(const CK_BYTE_PTR in, CK_BYTE_PTR out, CK_ULONG_PTR outlen);
int sc_bin_to_hex(const CK_BYTE_PTR in, CK_ULONG in_len, CK_BYTE_PTR out, CK_ULONG out_len, int in_sep);

#endif // PKCS11TEST_COMMON_H
