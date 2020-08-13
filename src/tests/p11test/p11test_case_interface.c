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
	/* XXX assuming two interfaces, PKCS#11 3.0 and 2.20 */
	assert_int_equal(count, 2);

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
	assert_string_equal(interfaces[0].pInterfaceName, "PKCS 11");
	assert_int_equal(((CK_VERSION *)interfaces[0].pFunctionList)->major, 3);
	assert_int_equal(((CK_VERSION *)interfaces[0].pFunctionList)->minor, 0);
	assert_int_equal(interfaces[0].flags, 0);
	assert_string_equal(interfaces[1].pInterfaceName, "PKCS 11");
	assert_int_equal(((CK_VERSION *)interfaces[1].pFunctionList)->major, 2);
	assert_int_equal(((CK_VERSION *)interfaces[1].pFunctionList)->minor, 20);
	assert_int_equal(interfaces[1].flags, 0);

	/* GetInterface with NULL name should give us default PKCS 11 one */
	rv = C_GetInterface(NULL, NULL, &interface, 0);
	assert_int_equal(rv, CKR_OK);
	assert_string_equal(interface->pInterfaceName, "PKCS 11");
	assert_int_equal(((CK_VERSION *)interface->pFunctionList)->major, 3);
	assert_int_equal(((CK_VERSION *)interface->pFunctionList)->minor, 0);
	assert_int_equal(interface->flags, 0);
	/* The function list should be the same */
	assert_ptr_equal(interfaces[0].pFunctionList, interface->pFunctionList);

	/* GetInterface with explicit 3.0 version */
	version.major = 3;
	version.minor = 0;
	rv = C_GetInterface((unsigned char *)"PKCS 11", &version, &interface, 0);
	assert_int_equal(rv, CKR_OK);
	assert_string_equal(interface->pInterfaceName, "PKCS 11");
	assert_int_equal(((CK_VERSION *)interface->pFunctionList)->major, 3);
	assert_int_equal(((CK_VERSION *)interface->pFunctionList)->minor, 0);
	assert_int_equal(interface->flags, 0);
	/* The function list should be the same */
	assert_ptr_equal(interfaces[0].pFunctionList, interface->pFunctionList);

	/* GetInterface with explicit 2.20 version */
	version.major = 2;
	version.minor = 20;
	rv = C_GetInterface((unsigned char *)"PKCS 11", &version, &interface, 0);
	assert_int_equal(rv, CKR_OK);
	assert_string_equal(interface->pInterfaceName, "PKCS 11");
	assert_int_equal(((CK_VERSION *)interface->pFunctionList)->major, 2);
	assert_int_equal(((CK_VERSION *)interface->pFunctionList)->minor, 20);
	assert_int_equal(interface->flags, 0);
	/* The function list should be the same here too */
	assert_ptr_equal(interfaces[1].pFunctionList, interface->pFunctionList);

	/* GetInterface with unknown interface  */
	rv = C_GetInterface((unsigned char *)"PKCS 11 other", NULL, &interface, 0);
	assert_int_equal(rv, CKR_ARGUMENTS_BAD);

	/* GetInterface with wrong version  */
	version.major = 2;
	version.minor = 50;
	rv = C_GetInterface((unsigned char *)"PKCS 11", &version, &interface, 0);
	assert_int_equal(rv, CKR_ARGUMENTS_BAD);

	/* GetInterface with unknown flags  */
	rv = C_GetInterface((unsigned char *)"PKCS 11", NULL, &interface, 2);
	assert_int_equal(rv, CKR_ARGUMENTS_BAD);
	free(interfaces);

	P11TEST_PASS(info);
}
