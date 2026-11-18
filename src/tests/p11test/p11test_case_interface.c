/*
 * p11test_case_interface.c: Test new PKCS #11 3.0 interface
 *
 * Copyright (C) 2020 Red Hat, Inc.
 *
 * Author: Jakub Jelen <jjelen@redhat.com>
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

#include "p11test_case_interface.h"
#include <dlfcn.h>

extern void *pkcs11_so;

/* The checks below describe OpenSC's own interfaces. Other modules offer
 * other sets, so they run only when C_GetInfo names OpenSC as manufacturer. */
static int
is_opensc_module(token_info_t *info)
{
	CK_INFO ck_info;
	const char *name = OPENSC_VS_FF_COMPANY_NAME;
	size_t len = strlen(name);

	if (info->function_pointer->C_GetInfo(&ck_info) != CKR_OK)
		return 0;
	if (len > sizeof(ck_info.manufacturerID))
		return 0;
	/* manufacturerID is padded with spaces, not terminated */
	return memcmp(ck_info.manufacturerID, name, len) == 0 &&
	       (len == sizeof(ck_info.manufacturerID) || ck_info.manufacturerID[len] == ' ');
}

void interface_test(void **state)
{
	token_info_t *info = (token_info_t *) *state;
	CK_RV (*C_GetInterfaceList)(CK_INTERFACE_PTR, CK_ULONG_PTR) = NULL;
	CK_RV (*C_GetInterface)(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS) = NULL;
	CK_RV rv;
	CK_ULONG count = 0;
	CK_INTERFACE *interfaces = NULL;
	CK_INTERFACE_PTR interface;
	CK_VERSION version;
	unsigned int i;

	P11TEST_START(info);

	C_GetInterfaceList = (CK_RV (*)(CK_INTERFACE_PTR, CK_ULONG_PTR)) dlsym(pkcs11_so, "C_GetInterfaceList");
	if (C_GetInterfaceList == NULL) {
		/* If the library does not have this function, it is probably not PKCS #11 3.0 */
		P11TEST_SKIP(info);
	}
	/* If we have C_GetInterfaceList, we should have also C_GetInterface */
	C_GetInterface = (CK_RV (*)(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS))
		dlsym(pkcs11_so, "C_GetInterface");
	assert_non_null(C_GetInterface);

	/* Invalid arguments */
	rv = C_GetInterfaceList(NULL, NULL);
	assert_int_equal(rv, CKR_ARGUMENTS_BAD);

	/* Get the count of interfaces */
	rv = C_GetInterfaceList(NULL, &count);
	assert_int_equal(rv, CKR_OK);
	/* Assume at least one interface here */
	assert_true(count > 0);

	interfaces = malloc(count * sizeof(CK_INTERFACE));
	assert_non_null(interfaces);

	/* Now get the actual interfaces */
	rv = C_GetInterfaceList(interfaces, &count);
	assert_int_equal(rv, CKR_OK);
	for (i = 0; i < count; i++) {
		printf("interface '%s' version %d.%d funcs %p flags 0x%lu\n",
			interfaces[i].pInterfaceName,
			((CK_VERSION *)interfaces[i].pFunctionList)->major,
			((CK_VERSION *)interfaces[i].pFunctionList)->minor,
			interfaces[i].pFunctionList,
			interfaces[i].flags);
	}
	/* OpenSC offers three interfaces: 3.2 (the default), 3.0 and 2.x */
	if (is_opensc_module(info)) {
		CK_VERSION version2;
		assert_int_equal(count, 3);
		for (i = 0; i < count; i++) {
			assert_string_equal((char *)interfaces[i].pInterfaceName, "PKCS 11");
			assert_int_equal(interfaces[i].flags, 0);
		}
		assert_int_equal(((CK_VERSION *)interfaces[0].pFunctionList)->major, 3);
		assert_int_equal(((CK_VERSION *)interfaces[0].pFunctionList)->minor, 2);
		assert_int_equal(((CK_VERSION *)interfaces[1].pFunctionList)->major, 3);
		assert_int_equal(((CK_VERSION *)interfaces[1].pFunctionList)->minor, 0);
		assert_int_equal(((CK_VERSION *)interfaces[2].pFunctionList)->major, 2);
		version2 = *(CK_VERSION *)interfaces[2].pFunctionList;

		/* GetInterface with NULL name should give us default PKCS 11 one */
		rv = C_GetInterface(NULL, NULL, &interface, 0);
		assert_int_equal(rv, CKR_OK);
		assert_ptr_equal(interfaces[0].pFunctionList, interface->pFunctionList);

		/* GetInterface with an explicit version gives the listed function list */
		version.major = 3;
		version.minor = 2;
		rv = C_GetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &version, &interface, 0);
		assert_int_equal(rv, CKR_OK);
		assert_ptr_equal(interfaces[0].pFunctionList, interface->pFunctionList);

		version.minor = 0;
		rv = C_GetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &version, &interface, 0);
		assert_int_equal(rv, CKR_OK);
		assert_ptr_equal(interfaces[1].pFunctionList, interface->pFunctionList);

		version = version2;
		rv = C_GetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &version, &interface, 0);
		assert_int_equal(rv, CKR_OK);
		assert_ptr_equal(interfaces[2].pFunctionList, interface->pFunctionList);
	}

	/* GetInterface with unknown interface  */
	rv = C_GetInterface((CK_UTF8CHAR_PTR) "PKCS 11 other", NULL, &interface, 0);
	assert_int_equal(rv, CKR_ARGUMENTS_BAD);

	/* GetInterface with wrong version  */
	version.major = 4;
	version.minor = 50;
	rv = C_GetInterface((CK_UTF8CHAR_PTR) "PKCS 11", &version, &interface, 0);
	assert_int_equal(rv, CKR_ARGUMENTS_BAD);

	/* GetInterface with unknown flags  */
	rv = C_GetInterface((CK_UTF8CHAR_PTR) "PKCS 11", NULL, &interface, 2);
	assert_int_equal(rv, CKR_ARGUMENTS_BAD);
	free(interfaces);

	P11TEST_PASS(info);
}
