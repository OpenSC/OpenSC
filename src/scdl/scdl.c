/*
 * Dynamic loading routines for various platforms, to
 * be used internally in several places.
 *
 * No interface for portable error handling, maybe
 * later.
 *
 * Copyright (C) 2003  Antti Tapaninen <aet@cc.hut.fi>
 *                     Olaf Kirch <okir@lst.de>
 *                     Stef Hoeben <stef.hoeben@zetes.com>
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __APPLE__
#include <Carbon/Carbon.h>
#endif
#include "scdl.h"

#define SCDL_MAGIC		0xbeefd00d

#define SCDL_TYPE_DLFCN		0x01
#define SCDL_TYPE_WIN32		0x02
#define SCDL_TYPE_MAC		0x03

struct scdl_context {
	unsigned int magic;
	void *handle;
	unsigned int type;
#if defined(__APPLE__)
	CFBundleRef bundleRef;
#endif
};
typedef struct scdl_context scdl_context_t;

#if defined(HAVE_DLFCN_H)
#include <dlfcn.h>

/*
 * Module loader for platforms that have dlopen
 */
static int
dlfcn_open(scdl_context_t *mod, const char *name)
{
	const char	**dir, *ldlist[64];
	char		pathbuf[4096], *ldenv = NULL;
	unsigned int	n = 0, flags = 0;

#ifdef RTLD_NOW
	flags |= RTLD_NOW;
#endif

	if (name[0] != '/') {
		/* in case of a relative path search the LD_LIBRARY_PATH */
		if ((ldenv = getenv("LD_LIBRARY_PATH"))
		    && (ldenv = strdup(ldenv))) {
			ldlist[n] = strtok(ldenv, ":");
			while (ldlist[n] != NULL && ++n < 63)
				ldlist[n] = strtok(NULL, ":");
		}
		ldlist[n] = NULL;

		for (dir = ldlist; *dir; dir++) {
			snprintf(pathbuf, sizeof(pathbuf), "%s/%s", *dir, name);
			mod->handle = dlopen(pathbuf, flags);
			if (mod->handle != NULL)
				break;
		}
	}

	if (mod->handle == NULL)
		mod->handle = dlopen(name, flags);

	if (ldenv)
		free(ldenv);

	mod->type = SCDL_TYPE_DLFCN;
	return (mod->handle? 0 : -1);
}

static int
dlfcn_close(scdl_context_t *mod)
{
	if (mod->handle)
		dlclose(mod->handle);
	mod->handle = NULL;
	return 0;
}

static void *
dlfcn_get_address(scdl_context_t *mod, const char *symbol)
{
	char sym_name[256];
	void *address;

	if (!mod->handle)
		return NULL;

	/* Some platforms might need a leading underscore for the symbol */
	snprintf(sym_name, sizeof(sym_name), "_%s", symbol);
	address = dlsym(mod->handle, sym_name);

	/* Failed? Try again without the leading underscore */
	if (address == NULL)
		address = dlsym(mod->handle, symbol);

	return address;
}

#endif
#ifdef _WIN32
#include <windows.h>

/*
 * Module loader for the Windows platform.
 */
static int
win32_open(scdl_context_t *mod, const char *name)
{
	mod->handle = LoadLibrary(name);
	mod->type = SCDL_TYPE_WIN32;

	return (mod->handle? 0 : GetLastError());
}

static int
win32_close(scdl_context_t *mod)
{
	if (mod->handle) {
		if (FreeLibrary(mod->handle)) {
			mod->handle = NULL;
			return 0;
		}
		else
			return -1;
	}

	return 0;
}

static void *
win32_get_address(scdl_context_t *mod, const char *symbol)
{
	if (!mod->handle)
		return NULL;
	return GetProcAddress(mod->handle, symbol);
}

#endif
#if defined(__APPLE__)
#include <mach-o/dyld.h>

/*
 * Module loader for MacOS X
 */
static int
mac_open(scdl_context_t *mod, const char *name)
{
	if (strstr(name, ".bundle")) {
		CFStringRef text = CFStringCreateWithFormat(
			NULL, NULL, CFSTR("%s"), name);
		CFURLRef urlRef = CFURLCreateWithFileSystemPath(
			kCFAllocatorDefault, text, kCFURLPOSIXPathStyle, 1);
		mod->bundleRef = CFBundleCreate(kCFAllocatorDefault, urlRef);
		CFRelease(urlRef);
		CFRelease(text);
		mod->handle = NULL;
	} else {
		mod->handle = (struct mach_header *) NSAddImage(name,
			NSADDIMAGE_OPTION_WITH_SEARCHING);
		mod->bundleRef = NULL;
	}
	mod->type = SCDL_TYPE_MAC;

	return (mod->handle == NULL && mod->bundleRef == NULL ? -1 : 0);
}

static int
mac_close(scdl_context_t *mod)
{
	if (mod->bundleRef != NULL) {
		CFBundleUnloadExecutable(mod->bundleRef);
		CFRelease(mod->bundleRef);
	}

	return 0;
}

static void *
mac_get_address(scdl_context_t *mod, const char *symbol)
{
	NSSymbol nssym = NULL;

	if (mod->bundleRef != NULL) {
		CFStringRef text = CFStringCreateWithFormat(
			NULL, NULL, CFSTR("%s"), symbol);
		nssym = CFBundleGetFunctionPointerForName(
			mod->bundleRef, text);
		CFRelease(text);
		return nssym;
	} else {
		char sym_name[4096];

		snprintf(sym_name, sizeof(sym_name), "_%s", symbol);
		nssym = NSLookupSymbolInImage((const struct mach_header *)
			mod->handle, sym_name,
			NSLOOKUPSYMBOLINIMAGE_OPTION_BIND_NOW);
		if (nssym == NULL)
			return NULL;
		return NSAddressOfSymbol(nssym);
	}
}
#endif

void *
scdl_open(const char *name)
{
	scdl_context_t *mod;
	int rv;

	mod = (scdl_context_t *) calloc(1, sizeof(*mod));
	if (mod == NULL)
		return NULL;
	mod->magic = SCDL_MAGIC;
#if defined(_WIN32)
	rv = win32_open(mod, name);
#elif defined(HAVE_DLFCN_H) && defined(__APPLE__)
	if (strstr(name, ".bundle") || strstr(name, ".dylib")) {
		rv = mac_open(mod, name);
	} else {
		rv = dlfcn_open(mod, name);
	}
#elif defined(__APPLE__)
	rv = mac_open(mod, name);
#elif defined(HAVE_DLFCN_H)
	rv = dlfcn_open(mod, name);
#else
	rv = -1;
#endif
	if (rv < 0) {
		memset(mod, 0, sizeof(*mod));
		free(mod);
		return NULL;
	}
	return (void *) mod;
}

int
scdl_close(void *module)
{
	scdl_context_t *mod = (scdl_context_t *) module;
	int rv;

	if (!mod || mod->magic != SCDL_MAGIC)
		return -1;
#if defined(_WIN32)
	rv = win32_close(mod);
#elif defined(HAVE_DLFCN_H) && defined(__APPLE__)
	switch(mod->type) {
	case SCDL_TYPE_MAC:
		rv = mac_close(mod);
		break;
	case SCDL_TYPE_DLFCN:
		rv = dlfcn_close(mod);
		break;
	}
#elif defined(__APPLE__)
	rv = mac_close(mod);
#elif defined(HAVE_DLFCN_H)
	rv = dlfcn_close(mod);
#endif
	memset(mod, 0, sizeof(*mod));
	free(mod);
	return 0;
}

void *
scdl_get_address(void *module, const char *symbol)
{
	scdl_context_t *mod = (scdl_context_t *) module;

	if (!mod || mod->magic != SCDL_MAGIC)
		return NULL;
#if defined(_WIN32)
	return win32_get_address(mod, symbol);
#elif defined(HAVE_DLFCN_H) && defined(__APPLE__)
	switch(mod->type) {
	case SCDL_TYPE_MAC:
		return mac_get_address(mod, symbol);
		break;
	case SCDL_TYPE_DLFCN:
		return dlfcn_get_address(mod, symbol);
		break;
	}
#elif defined(__APPLE__)
	return mac_get_address(mod, symbol);
#elif defined(HAVE_DLFCN_H)
	return dlfcn_get_address(mod, symbol);
#endif
	return NULL;
}
