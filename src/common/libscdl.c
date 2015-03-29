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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "libscdl.h"

#ifdef WIN32
#include <windows.h>
void *sc_dlopen(const char *filename)
{
	return (void *)LoadLibraryA(filename);
}

void *sc_dlsym(void *handle, const char *symbol)
{
	return GetProcAddress((HMODULE)handle, symbol);
}

const char *sc_dlerror()
{
	return "LoadLibrary/GetProcAddress failed";
}

int sc_dlclose(void *handle)
{
	return FreeLibrary((HMODULE)handle);
}
#else
#include <dlfcn.h>
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
#endif
