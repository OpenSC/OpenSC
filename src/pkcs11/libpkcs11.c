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
#ifdef __APPLE__
#include <Carbon/Carbon.h>
#endif

#define MAGIC			0xd00bed00

#define DL_TYPE_DLFCN		0x01
#define DL_TYPE_WIN32		0x02
#define DL_TYPE_MAC		0x03

#if defined(_WIN32)
#define DEFAULT_MODULE_NAME	"opensc-pkcs11";
#elif defined(HAVE_DLFCN_H) && defined(__APPLE__)
#define DEFAULT_MODULE_NAME	"opensc-pkcs11.so";
#elif defined(__APPLE__)
#define DEFAULT_MODULE_NAME	"OpenSC PKCS#11.bundle";
#else
#define DEFAULT_MODULE_NAME	"opensc-pkcs11.so";
#endif

struct sc_pkcs11_module {
	unsigned int _magic;
	void *_dl_handle;
	unsigned int _type;
#if defined(__APPLE__)
	CFBundleRef bundleRef;
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

#if defined(HAVE_DLFCN_H)
#include <dlfcn.h>

/*
 * Module loader for platforms that have dlopen
 *
 * This is intentionally primitive; we may want a more
 * elaborate loader in libopensc one day
 */
int
dl_dlopen(struct sc_pkcs11_module *mod, const char *name)
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

	mod->_type = DL_TYPE_DLFCN;
	return (mod->_dl_handle? 0 : -1);
}

int
dl_dlclose(struct sc_pkcs11_module *mod)
{
	if (mod->_dl_handle)
		dlclose(mod->_dl_handle);
	mod->_dl_handle = NULL;
	return 0;
}

void *
dl_dlsym(sc_pkcs11_module_t *mod, const char *name)
{
	char sym_name[256];
	void *address;

	if (!mod->_dl_handle)
		return NULL;

	/* Some platforms might need a leading underscore for the symbol */
	snprintf(sym_name, sizeof(sym_name), "_%s", name);
	address = dlsym(mod->_dl_handle, sym_name);

	/* Failed? Try again without the leading underscore */
	if (address == NULL)
		address = dlsym(mod->_dl_handle, name);

	return address;
}

#endif
#ifdef _WIN32
#include <windows.h>

/*
 * Module loader for the Windows platform.
 */
int
win32_dlopen(struct sc_pkcs11_module *mod, const char *name)
{
	mod->_dl_handle = LoadLibrary(name);
	mod->_type = DL_TYPE_WIN32;

	return (mod->_dl_handle? 0 : GetLastError());
}

int
win32_dlclose(struct sc_pkcs11_module *mod)
{
	if (mod->_dl_handle) {
		if (FreeLibrary(mod->_dl_handle)) {
			mod->_dl_handle = NULL;
			return 0;
		}
		else
			return -1;
	}

	return 0;
}

void *
win32_dlsym(sc_pkcs11_module_t *mod, const char *name)
{
	if (!mod->_dl_handle)
		return NULL;
	return GetProcAddress(mod->_dl_handle, name);
}

#endif
#if defined(__APPLE__)
#include <mach-o/dyld.h>

/*
 * Module loader for MacOS X
 */
int
mac_dlopen(struct sc_pkcs11_module *mod, const char *name)
{
	if (strstr(name, ".bundle")) {
		CFStringRef text = CFStringCreateWithFormat(
			NULL, NULL, CFSTR("%s"), name);
		CFURLRef urlRef = CFURLCreateWithFileSystemPath(
			kCFAllocatorDefault, text, kCFURLPOSIXPathStyle, 1);
		mod->bundleRef = CFBundleCreate(kCFAllocatorDefault, urlRef);
		CFRelease(urlRef);
		CFRelease(text);
		mod->_dl_handle = NULL;
	} else {
		mod->_dl_handle = (struct mach_header *) NSAddImage(name,
			NSADDIMAGE_OPTION_WITH_SEARCHING);
		mod->bundleRef = NULL;
	}
	mod->_type = DL_TYPE_MAC;

	return (mod->_dl_handle == NULL && mod->bundleRef == NULL ? -1 : 0);
}

int
mac_dlclose(struct sc_pkcs11_module *mod)
{
	if (mod->bundleRef != NULL) {
		CFBundleUnloadExecutable(mod->bundleRef);
		CFRelease(mod->bundleRef);
	}

	return 0;
}

void *
mac_dlsym(sc_pkcs11_module_t *mod, const char *name)
{
	NSSymbol symbol = NULL;

	if (mod->bundleRef != NULL) {
		CFStringRef text = CFStringCreateWithFormat(
			NULL, NULL, CFSTR("%s"), name);
		symbol = CFBundleGetFunctionPointerForName(
			mod->bundleRef, text);
		CFRelease(text);
		return symbol;
	} else {
		char sym_name[4096];

		snprintf(sym_name, sizeof(sym_name), "_%s", name);
		symbol = NSLookupSymbolInImage((const struct mach_header *)
			mod->_dl_handle, sym_name,
			NSLOOKUPSYMBOLINIMAGE_OPTION_BIND_NOW);
		if (symbol == NULL)
			return NULL;
		return NSAddressOfSymbol(symbol);
	}
}
#endif

int
sys_dlopen(struct sc_pkcs11_module *mod, const char *name)
{
	if (name == NULL)
		name = DEFAULT_MODULE_NAME;
#if defined(_WIN32)
	return win32_dlopen(mod, name);
#elif defined(HAVE_DLFCN_H) && defined(__APPLE__)
	if (strstr(name, ".bundle") || strstr(name, ".dylib")) {
		return mac_dlopen(mod, name);
	} else {
		return dl_dlopen(mod, name);
	}
#elif defined(__APPLE__)
	return mac_dlopen(mod, name);
#elif defined(HAVE_DLFCN_H)
	return dl_dlopen(mod, name);
#endif
	return -1;
}

int
sys_dlclose(struct sc_pkcs11_module *mod)
{
#if defined(_WIN32)
	return win32_dlclose(mod);
#elif defined(HAVE_DLFCN_H) && defined(__APPLE__)
	switch(mod->_type) {
	case DL_TYPE_MAC:
		return mac_dlclose(mod);
		break;
	case DL_TYPE_DLFCN:
		return dl_dlclose(mod);
		break;
	}
#elif defined(__APPLE__)
	return mac_dlclose(mod);
#elif defined(HAVE_DLFCN_H)
	return dl_dlclose(mod);
#endif
	return 0;
}

void *
sys_dlsym(sc_pkcs11_module_t *mod, const char *name)
{
#if defined(_WIN32)
	return win32_dlsym(mod, name);
#elif defined(HAVE_DLFCN_H) && defined(__APPLE__)
	switch(mod->_type) {
	case DL_TYPE_MAC:
		return mac_dlsym(mod, name);
		break;
	case DL_TYPE_DLFCN:
		return dl_dlsym(mod, name);
		break;
	}
#elif defined(__APPLE__)
	return mac_dlsym(mod, name);
#elif defined(HAVE_DLFCN_H)
	return dl_dlsym(mod, name);
#endif
	return NULL;
}
