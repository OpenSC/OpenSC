/*
 * libscdl.c: wrappers for dlfcn() interfaces
 *
 * Copyright (C) 2010  Martin Paljak <martin@martinpaljak.net>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "config.h"

#include "libscdl.h"

#ifdef HAVE_LTDL_H
#include <ltdl.h>
/* libltdl is present, pass all calls to it */

void *sc_dlopen(const char *filename)
{
	return (void *)lt_dlopen(filename);
}

void *sc_dlsym(void *handle, const char *symbol)
{
	return lt_dlsym((lt_dlhandle)handle, symbol);
}

const char *sc_dlerror(void)
{
	return lt_dlerror();
}

int sc_dlclose(void *handle)
{
	return lt_dlclose((lt_dlhandle)handle);
}

#else
/* Small wrappers for native functions, bypassing libltdl */
#ifdef _WIN32
/* Use Windows calls */
void *sc_dlopen(const char *filename)
{
	return (void *)LoadLibrary(filename);
}

void *sc_dlsym(void *handle, const char *symbol)
{
	return GetProcAddress(handle, symbol);
}

const char *sc_dlerror()
{
	return "LoadLibrary/GetProcAddress failed";
}

int sc_dlclose(void *handle)
{
	return FreeLibrary(handle);
}

#elif defined(HAVE_DLFCN_H)
#include <dlfcn.h>
/* Use native interfaces */
void *sc_dlopen(const char *filename)
{
	return dlopen(filename, RTLD_LAZY);
}

void *sc_dlsym(void *handle, const char *symbol)
{
	return dlsym(handle, symbol);
}

const char *sc_dlerror(void)
{
	return dlerror();
}

int sc_dlclose(void *handle)
{
	return dlclose(handle);
}

#else
/* Dynamic loading is not available */
void *sc_dlopen(const char *filename)
{
	return NULL;
}

void *sc_dlsym(void *handle, const char *symbol)
{
	return NULL;
}

const char *sc_dlerror()
{
	return "dlopen() functionality not available";
}

int sc_dlclose(void *handle)
{
	return 0;
}

#endif
#endif
