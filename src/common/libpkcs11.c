/*
 * Convenience pkcs11 library that can be linked into an application,
 * and will bind to a specific pkcs11 module.
 *
 * Copyright (C) 2002  Olaf Kirch <okir@suse.de>
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "pkcs11/pkcs11.h"

#include "common/libscdl.h"
#include "common/libpkcs11.h"

#define MAGIC			0xd00bed00

struct sc_pkcs11_module {
	unsigned int _magic;
	void *handle; /* dlopen handle */
	CK_VERSION version; /* authoritative version number */
	CK_FUNCTION_LIST_PTR function_list; /* v2 functions lists */
	CK_INTERFACE_PTR interface; /* v3 interface */
};
typedef struct sc_pkcs11_module sc_pkcs11_module_t;

/*
 * Load a module - this will load the shared object, call C_GetInterface or C_GetFunctionList
 * and get the list of function pointers for PKCS#11 2.*
 * To use the PKCS#11 3.* API, you need to use C_GetModuleInterface() below.
 */
void *
C_LoadModule(const char *mspec, CK_FUNCTION_LIST_PTR_PTR funcs)
{
	sc_pkcs11_module_t *mod;
	CK_RV rv, (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);
	CK_RV (*c_get_interface)(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS);
	mod = calloc(1, sizeof(*mod));
	if (mod == NULL) {
		return NULL;
	}
	mod->_magic = MAGIC;

	if (mspec == NULL) {
		free(mod);
		return NULL;
	}
	mod->handle = sc_dlopen(mspec);
	if (mod->handle == NULL) {
		fprintf(stderr, "sc_dlopen failed: %s\n", sc_dlerror());
		goto failed;
	}

	c_get_interface = (CK_RV (*)(CK_UTF8CHAR_PTR, CK_VERSION_PTR, CK_INTERFACE_PTR_PTR, CK_FLAGS))
		sc_dlsym(mod->handle, "C_GetInterface");
	if (c_get_interface) {
		/* Get default PKCS #11 interface */
		rv = c_get_interface((CK_UTF8CHAR_PTR) "PKCS 11", NULL, &mod->interface, 0);
		if (rv == CKR_OK) {
			/* PKCS#11 2.* compatible API */
			mod->function_list = mod->interface->pFunctionList;
			mod->version = mod->function_list->version;
			/* this is actually 3.* function list, but it starts with the same fields as 2.* so
			 * we can return it here too. Only for new functions, it needs to be pulled from the
			 * structure. */
			*funcs = mod->function_list;
			return (void *)mod;
		} else {
			fprintf(stderr, "C_GetInterface failed %lx, retry 2.x way", rv);
		}
	}

	/* Get the list of function pointers */
	c_get_function_list = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))
				sc_dlsym(mod->handle, "C_GetFunctionList");
	if (!c_get_function_list)
		goto failed;
	rv = c_get_function_list(funcs);
	if (rv == CKR_OK) {
		mod->version = (*funcs)->version;
		if (mod->version.major > 2) {
			/* SoftHSM bug: The version in function list SHOULD NOT be > 2. Override with last
			 * valid 2.* version:
			 * https://github.com/softhsm/SoftHSMv2/issues/839
			 */
			mod->version.major = 2;
			mod->version.minor = 40;
		}
		return (void *)mod;
	} else {
		fprintf(stderr, "C_GetFunctionList failed %lx", rv);
		rv = C_UnloadModule((void *) mod);
		if (rv == CKR_OK)
			mod = NULL; /* already freed */
	}
failed:
	if (mod && mod->handle)
		sc_dlclose(mod->handle);
	free(mod);
	return NULL;
}

/*
 * Return the PKCS#11 API version.
 *
 * This is not the same as the version provided in the function list returned
 * from C_LoadModule() as some broken PKCS#11 modules might include mismatching
 * versions in C_GetFunctionList().
 */
CK_VERSION_PTR
C_GetModuleVersion(void *module)
{
	sc_pkcs11_module_t *mod = (sc_pkcs11_module_t *)module;

	return &mod->version;
}

/*
 * Return the PKCS#11 3.* API interface from the loaded module.
 * For PKCS#11 2.* modules, this returns NULL and 2.* function list
 * from the C_LoadModule needs to be used.
 */
CK_INTERFACE_PTR
C_GetModuleInterface(void *module)
{
	sc_pkcs11_module_t *mod = (sc_pkcs11_module_t *)module;

	if (mod->version.major > 2) {
		return mod->interface;
	}
	return NULL;
}

/*
 * Unload a pkcs11 module.
 * The calling application is responsible for cleaning up
 * and calling C_Finalize
 */
CK_RV
C_UnloadModule(void *module)
{
	sc_pkcs11_module_t *mod = (sc_pkcs11_module_t *)module;

	if (!mod || mod->_magic != MAGIC)
		return CKR_ARGUMENTS_BAD;

	if (mod->handle != NULL && sc_dlclose(mod->handle) < 0)
		return CKR_FUNCTION_FAILED;

	free(mod);
	return CKR_OK;
}
