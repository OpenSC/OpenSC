/*
 * Convenience pkcs11 library that can be linked into an application,
 * and will bind to a specific pkcs11 module.
 *
 * Copyright (C) 2002  Olaf Kirch <okir@lst.de>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "pkcs11.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <opensc/scdl.h>

#define MAGIC			0xd00bed00

#if defined(_WIN32)
#define DEFAULT_MODULE_NAME	"opensc-pkcs11";
#elif defined(HAVE_DLFCN_H) && defined(__APPLE__)
#define DEFAULT_MODULE_NAME	"opensc-pkcs11.so";
#elif defined(__APPLE__)
#define DEFAULT_MODULE_NAME	"opensc-pkcs11.bundle";
#else
#define DEFAULT_MODULE_NAME	"opensc-pkcs11.so";
#endif

struct sc_pkcs11_module {
	unsigned int _magic;
	scdl_context_t *handle;
};

/*
 * Load a module - this will load the shared object, call
 * C_Initialize, and get the list of function pointers
 */
sc_pkcs11_module_t *
C_LoadModule(const char *mspec, CK_FUNCTION_LIST_PTR_PTR funcs)
{
	sc_pkcs11_module_t *mod;
	CK_RV (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);
	int rv;

	mod = (sc_pkcs11_module_t *) calloc(1, sizeof(*mod));
	mod->_magic = MAGIC;

	if (mspec == NULL)
		mspec = DEFAULT_MODULE_NAME;
	mod->handle = scdl_open(mspec);
	if (mod->handle == NULL)
		goto failed;

	/* Get the list of function pointers */
	c_get_function_list = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))
				scdl_get_address(mod->handle, "C_GetFunctionList");
	if (!c_get_function_list)
		goto failed;
	rv = c_get_function_list(funcs);
	if (rv == CKR_OK)
		return mod;

failed:	C_UnloadModule(mod);
	return NULL;
}

/*
 * Unload a pkcs11 module.
 * The calling application is responsible for cleaning up
 * and calling C_Finalize
 */
CK_RV
C_UnloadModule(sc_pkcs11_module_t *mod)
{
	if (!mod || mod->_magic != MAGIC)
		return CKR_ARGUMENTS_BAD;

	if (scdl_close(mod->handle) < 0)
		return CKR_FUNCTION_FAILED;

	memset(mod, 0, sizeof(*mod));
	free(mod);
	return CKR_OK;
}
