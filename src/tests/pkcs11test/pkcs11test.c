/*
 * pkcs11test.c: Test suite for PKCS#11 Test Cases
 *
 * Copyright (C) 2021 Red Hat, Inc.
 *
 * Author: Veronika Hanulikova <vhanulik@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <dlfcn.h>
#include <getopt.h>

#include "pkcs11/pkcs11.h"
#include "pkcs11test_types.h"
#include "pkcs11test_process.h"

#define DEFAULT_P11LIB	"../../pkcs11/.libs/opensc-pkcs11.so"

void
display_usage()
{
	fprintf(stdout,
		" Usage:\n"
		" \t./pkcs11test [OPTIONS]\n"
		" Options:\n"
		" \t-m, --module module_path Path to tested module (Default: "DEFAULT_P11LIB")\n"
		" \t-p, --pin	pin		 Application PIN\n"
		" \t-o, --out	filename	File to write an output log\n"
		" \t-v, --verbose			Verbose log output\n"
		" \t-h, --help			   This help\n"
		"\n");
}

// clang-format off
static const struct option options[] = {
	{ "module",		1, NULL,		'm' },
	{ "pin",		1, NULL,		'p' },
	{ "slot",		1, NULL,		's' },
	{ "input-file",		1, NULL,		'i' },
	{ "output-file",	1, NULL,		'o' },
	{ "verbose",		0, NULL,		'v' },
	{ "help",		0, NULL,		'h' },
	{ NULL, 0, NULL, 0 }
};
// clang-format on

int
pkcs11test_parse_options(int argc, char **argv, struct test_info *info)
{
	int c = 0, long_optind = 0;
	if (info == NULL) {
		return PKCS11TEST_INVALID_ARGUMENTS;
	}

	while ((c = getopt_long(argc, argv, "?hm:s:p:i:o:v", options, &long_optind)) != -1) {
		switch (c) {
			case 'i':
				info->input_file = strdup(optarg);
				if (info->input_file == NULL) {
					return PKCS11TEST_INTERNAL_ERROR;
				}
				break;
			case 'o':
				info->output_file = strdup(optarg);
				if (info->output_file == NULL) {
					return PKCS11TEST_INTERNAL_ERROR;
				}
				break;
			case 'm':
				info->library_path = strdup(optarg);
				if (info->library_path == NULL) {
					return PKCS11TEST_INTERNAL_ERROR;
				}
				break;
			case 'p':
				info->pin = (CK_UTF8CHAR *)strdup(optarg);
				if (info->pin == NULL) {
					return PKCS11TEST_INTERNAL_ERROR;
				}
				info->pin_length = strlen(optarg);
				break;
			case 'v':
				// TODO
				break;
			case 'h':
			case '?':
				display_usage();
				return 0;
			default:
				display_usage();
				return PKCS11TEST_INTERNAL_ERROR;
		}
	}
	return PKCS11TEST_SUCCESS;
}

int
pkcs11test_initialiaze_pkcs11(struct test_info *info)
{
	CK_RV rv;
	CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR) = 0;

	log("Opening PKCS#11 module...");

	if(strlen(info->library_path) == 0) {
		error_log("You have to specify path to PKCS#11 library.");
		return PKCS11TEST_PKCS11_ERROR;
	}

	info->pkcs11_so = dlopen(info->library_path, RTLD_NOW);

	if (!info->pkcs11_so) {
		error_log("Error loading pkcs#11 so: %s\n", dlerror());
		return PKCS11TEST_PKCS11_ERROR;
	}

	C_GetFunctionList = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR)) dlsym(info->pkcs11_so, "C_GetFunctionList");

	if (!C_GetFunctionList) {
		error_log("Could not get function list: %s\n", dlerror());
		return PKCS11TEST_PKCS11_ERROR;
	}

	rv = C_GetFunctionList(&info->pkcs11);
	if (CKR_OK != rv) {
		error_log("C_GetFunctionList call failed: 0x%.8lX", rv);
		return PKCS11TEST_PKCS11_ERROR;
	}

	log("PKCS#11 module prepared");
	return PKCS11TEST_SUCCESS;
}

void
pkcs11test_info_destroy(struct test_info *info)
{
	if(info->pkcs11_so) {
		dlclose(info->pkcs11_so);
	}
	free(info->library_path);
	free(info->pin);
	(void) info->pin_length;
}

int
main(int argc, char **argv)
{
	int retval = 0;
	struct test_info info = { 0 };
	xmlDoc *test_doc = NULL;

	if (pkcs11test_parse_options(argc, argv, &info) != PKCS11TEST_SUCCESS) {
		error_log("Invallid arguments");
		retval = 1;
		goto err;
	}

	if (info.input_file == NULL) {
		error_log("No input file with test cases");
		retval = 1;
		goto err;
	}

	if (info.library_path == NULL) {
		log("Falling back to the default PKCS#11 library %s", DEFAULT_P11LIB);
		info.library_path = strdup(DEFAULT_P11LIB);
		if (info.library_path == NULL) {
			retval = 1;
			goto err;
		}
	}

	/* Open XML file */
	test_doc = xmlReadFile(info.input_file, NULL, 0);
	if (test_doc == NULL) {
		error_log("Cannot read XML test file");
		retval = 1;
		goto err;
	}

	/* Initialize PKCS#1 function list */
	if (pkcs11test_initialiaze_pkcs11(&info) != 0) {
		retval = 1;
		goto err;
	}

	/* Run test */
	if (pkcs11test_run(test_doc, &info) != PKCS11TEST_SUCCESS) {
		error_log("Testing harness failed.");
		retval = 1;
		goto err;
	}

	/* Clean resources */
err:
	log("Cleaning up");
	pkcs11test_info_destroy(&info);
	xmlFreeDoc(test_doc);
	return retval;
}
