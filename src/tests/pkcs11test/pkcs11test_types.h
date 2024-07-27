#ifndef PKCS11TEST_TYPES_H
#define PKCS11TEST_TYPES_H

#include <stdint.h>
#include "pkcs11/pkcs11.h"

#define PKCS11TEST_CALLING_FUNC 0x01
#define PKCS11TEST_RETURN_FUNC  0x02

#define PKCS11TEST_SUCCESS			 0x00
#define PKCS11TEST_INVALID_ARGUMENTS   -1100
#define PKCS11TEST_INTERNAL_ERROR   -1101
#define PKCS11TEST_PKCS11_ERROR   -1102
#define PKCS11TEST_XML_ERROR   -1103
#define PKCS11TEST_NO_RV   -1104
#define PKCS11TEST_PARSE_ERROR   -1105
#define PKCS11TEST_INVALID_PARAM_NAME   -1106
#define PKCS11TEST_DATA_NOT_FOUND   -1107
#define PKCS11TEST_PARAM_ABSENT   -1108
#define PKCS11TEST_PROP_ABSENT   -1109
#define PKCS11TEST_INVALID_VALUE_NAME   -1110

#define log(fmt, ...) \
	do { \
		fprintf(stdout, fmt "\n", ##__VA_ARGS__); \
	} while (0)

#define error_log(fmt, ...) \
	do { \
		fprintf(stderr, fmt "\n", ##__VA_ARGS__); \
	} while (0)

struct test_info
{
	void *pkcs11_so;
	CK_FUNCTION_LIST_PTR pkcs11;
	CK_UTF8CHAR* pin;
	size_t pin_length;
	char *library_path;
	char *input_file;
	char *output_file;
};

/**
 * Symbolic identifiers SHALL be of the form ${ParameterName}.
 * Wherever a symbolic identifier occurs in a test case the implementation must
 * replace it with a reasonable appearing datum of the expected type.
 * The symbolic identifier may reference return parameters or array or list items by index number.
 * Array index numbers SHALL be of the form ${ParmeterName[ArrayIndex]} and the first element SHALL be indicated by index zero. 
 * The symbolic identifier may reference elements nested within other elements.
 * Nested references SHALL be of the form ${ParameterName.SubElement} and MAY also include an array index.
*/
struct internal_data
{
	void *data;
	size_t length;
	char identifier[40];
	struct internal_data *next;
};

/* PKCS#11 function drivers */
typedef int (*process_func)(xmlNode *, xmlNode *, struct internal_data **, struct test_info *);
struct function_mapping {
	const char *name;
	process_func process_func;
};

/* Parser functions */
typedef int (*parser_func)(struct test_info *, struct internal_data **, xmlNode *, CK_VOID_PTR, CK_ULONG_PTR);
typedef int (*prop_parser_func)(struct test_info *, struct internal_data **, xmlNode *, const char **, CK_VOID_PTR, CK_ULONG_PTR);

struct prop_parse_map {
	const char *name;
	CK_VOID_PTR ptr;
	CK_ULONG_PTR length;
	prop_parser_func parser_func;
};

struct param_parse_map {
	const char *name;
	CK_VOID_PTR ptr;
	CK_ULONG_PTR length;
	parser_func parser_func;
};

/* Checker functions*/
typedef int (*check_func)(struct test_info *, struct internal_data **, xmlNode *, CK_VOID_PTR, CK_ULONG_PTR);
typedef int (*prop_check_func)(struct test_info *, struct internal_data **, xmlNode *, const char **, CK_VOID_PTR, CK_ULONG_PTR length);

struct prop_check_map {
	const char *name;
	CK_VOID_PTR ptr;
	CK_ULONG_PTR length;
	prop_check_func check_func;
};

struct param_check_map {
	const char *name;
	CK_VOID_PTR ptr;
	CK_ULONG_PTR length;
	check_func check_func;
};

#endif // PKCS11TEST_TYPES_H
