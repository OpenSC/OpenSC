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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "libscdl.h"

#ifdef _WIN32
#include <shlwapi.h>
#include <stdio.h>
#include <windows.h>

void *sc_dlopen(const char *filename)
{
	DWORD flags = PathIsRelativeA(filename) ? 0 : LOAD_WITH_ALTERED_SEARCH_PATH;
	return (void *)LoadLibraryExA(filename, NULL, flags);
}

void *sc_dlsym(void *handle, const char *symbol)
{
	return GetProcAddress((HMODULE)handle, symbol);
}

const char *sc_dlerror()
{
	static char msg[1024];
	DWORD err = GetLastError();
	DWORD rv = 0;

	if (err == ERROR_BAD_EXE_FORMAT) {
		return "LoadLibrary/GetProcAddress failed: check module architecture matches application architecture";
	}

	rv = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			msg, sizeof(msg), NULL);
	if (rv == 0) {
		snprintf(msg, sizeof(msg), "LoadLibrary/GetProcAddress failed: %lx", err);
	}
	return msg;
}

int sc_dlclose(void *handle)
{
	return FreeLibrary((HMODULE)handle);
}

#else

#ifdef HAVE_DLMOPEN
#define _GNU_SOURCE
#endif
#include <dlfcn.h>

void *sc_dlopen(const char *filename)
{
	return dlopen(filename, RTLD_LAZY | RTLD_LOCAL
#ifdef RTLD_DEEPBIND
			| RTLD_DEEPBIND
#endif
			);
}

void *sc_dlmopen(const char *filename)
{
#ifdef HAVE_DLMOPEN
	return dlmopen(LM_ID_NEWLM, filename, RTLD_LAZY | RTLD_LOCAL);
#else
	return sc_dlopen(filename);
#endif
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
