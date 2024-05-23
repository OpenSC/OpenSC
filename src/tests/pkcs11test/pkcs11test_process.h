#ifndef PKCS11TEST_PROCESS_H
#define PKCS11TEST_PROCESS_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "pkcs11/pkcs11.h"
#include "pkcs11test_types.h"

/**
 * Test harness for PKCS#11 test cases in XML
 * 
 * @param test_doc  pointer parsed document in stored in xmlDoc
 * @param info      test parameters
 * @return PKCS11TEST_SUCCESS when test finished successfully, particular error code otherwise
 */
int pkcs11test_run(xmlDoc *test_doc, struct test_info *info);

#endif // PKCS11TEST_PROCESS_H
