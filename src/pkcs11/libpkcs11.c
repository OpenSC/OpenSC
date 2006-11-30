/*
 * Convenience pkcs11 library that can be linked into an application,
 * and will bind to a specific pkcs11 module.
 *
 * Copyright (C) 2002  Olaf Kirch <okir@lst.de>
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "sc-pkcs11.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ltdl.h>

#define MAGIC			0xd00bed00

struct sc_pkcs11_module {
	unsigned int _magic;
	lt_dlhandle handle;
};
typedef struct sc_pkcs11_module sc_pkcs11_module_t;

/*
 * Load a module - this will load the shared object, call
 * C_Initialize, and get the list of function pointers
 */
void *
C_LoadModule(const char *mspec, CK_FUNCTION_LIST_PTR_PTR funcs)
{
	sc_pkcs11_module_t *mod;
	CK_RV (*c_get_function_list)(CK_FUNCTION_LIST_PTR_PTR);
	int rv;

	lt_dlinit();

	mod = (sc_pkcs11_module_t *) calloc(1, sizeof(*mod));
	mod->_magic = MAGIC;

	if (mspec == NULL)
		mspec = PKCS11_DEFAULT_MODULE_NAME;
	mod->handle = lt_dlopen(mspec);
	if (mod->handle == NULL) {
#if 0
		fprintf(stderr, "lt_dlopen failed: %s\n", lt_dlerror());
#endif
		goto failed;
	}

	/* Get the list of function pointers */
	c_get_function_list = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))
				lt_dlsym(mod->handle, "C_GetFunctionList");
	if (!c_get_function_list)
		goto failed;
	rv = c_get_function_list(funcs);
	if (rv == CKR_OK)
		return (void *) mod;

failed:
	C_UnloadModule((void *) mod);
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
	sc_pkcs11_module_t *mod = (sc_pkcs11_module_t *) module;

	if (!mod || mod->_magic != MAGIC)
		return CKR_ARGUMENTS_BAD;

	if (lt_dlclose(mod->handle) < 0)
		return CKR_FUNCTION_FAILED;

	memset(mod, 0, sizeof(*mod));
	free(mod);
	return CKR_OK;
}
