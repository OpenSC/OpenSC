/*
 * Convenience pkcs11 library that can be linked into an application,
 * and will bind to a specific pkcs11 module.
 *
 * Copyright (C) 2002  Olaf Kirch <okir@lst.de>
 */

#include "pkcs11.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MAGIC			0xd00bed00

struct sc_pkcs11_module {
	unsigned int		_magic;
#if defined(linux)
	void *			_dl_handle;
#endif
};

static int	sys_dlopen(sc_pkcs11_module_t *, const char *);
static int	sys_dlclose(sc_pkcs11_module_t *);
static void *	sys_dlsym(sc_pkcs11_module_t *, const char *);

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
	if (sys_dlopen(mod, mspec) < 0)
		goto failed;

	/* Get the list of function pointers */
	c_get_function_list = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))
				sys_dlsym(mod, "C_GetFunctionList");
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

	if (sys_dlclose(mod) < 0)
		return CKR_FUNCTION_FAILED;

	memset(mod, 0, sizeof(*mod));
	free(mod);
	return CKR_OK;
}

#ifdef linux
#include <dlfcn.h>

/*
 * Module loader for platforms that have dlopen
 *
 * This is intentionally primitive; we may want a more
 * elaborate loader in libopensc one day
 */
int
sys_dlopen(struct sc_pkcs11_module *mod, const char *name)
{
	const char	**dir, *ldlist[64];
	char		pathbuf[4096], *ldenv;
	unsigned int	n = 0;

	if ((ldenv = getenv("LD_LIBRARY_PATH")) 
	 && (ldenv = strdup(ldenv))) {
		ldlist[n] = strtok(ldenv, ":");
		while (ldlist[n] != NULL && ++n < 63)
			ldlist[n] = strtok(NULL, ":");
	}
	ldlist[n] = NULL;

	if (name == NULL)
		name = "opensc-pkcs11.so";

	for (dir = ldlist; *dir; dir++) {
		snprintf(pathbuf, sizeof(pathbuf), "%s/%s", *dir, name);
		mod->_dl_handle = dlopen(pathbuf, RTLD_NOW);
		if (mod->_dl_handle != NULL)
			break;
	}

	if (mod->_dl_handle == NULL)
		mod->_dl_handle = dlopen(name, RTLD_NOW);

	if (ldenv)
		free(ldenv);

	return (mod->_dl_handle? 0 : -1);
}

int
sys_dlclose(struct sc_pkcs11_module *mod)
{
	if (mod->_dl_handle)
		dlclose(mod->_dl_handle);
	mod->_dl_handle = NULL;
	return 0;
}


void *
sys_dlsym(sc_pkcs11_module_t *mod, const char *name)
{
	if (!mod->_dl_handle)
		return NULL;
	return dlsym(mod->_dl_handle, name);
}

#endif
