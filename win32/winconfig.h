#ifndef _OPENSC_WINCONFIG_H
#define _OPENSC_WINCONFIG_H

#include <stdio.h>
#include <sys/stat.h>
#include <sys/timeb.h>
#include <windows.h>
#include <winscard.h>

#ifdef _MSC_VER
// TODO fix data truncation instead of disabling them
// VC++ 2015 changes truncation warnings from 4244 to 4267.
#pragma warning(disable : 4267)
#pragma warning(disable : 4244)
#endif

#ifndef strcasecmp
#define strcasecmp stricmp
#endif

#ifndef strncasecmp
#define strncasecmp strnicmp
#endif

#ifndef vsnprintf
#define vsnprintf _vsnprintf
#endif

#ifndef snprintf
#define snprintf _snprintf
#endif

#ifndef R_OK
#define R_OK 4 /* test whether readable.  */
#define W_OK 2 /* test whether writable.  */
#define X_OK 1 /* test whether executable. */
#define F_OK 0 /* test whether exist.  */
#endif

#ifndef S_IRUSR
#define S_IRUSR S_IREAD
#endif

#ifndef S_IWUSR
#define S_IWUSR S_IWRITE
#endif

#define HAVE_STRNLEN
#define HAVE_IO_H
#define ENABLE_PCSC
#define HAVE_WINSCARD_H
#ifndef DEFAULT_PCSC_PROVIDER
#define DEFAULT_PCSC_PROVIDER "winscard.dll"
#endif

#define ENABLE_SHARED 1
#define ENABLE_NOTIFY 1

#define PATH_MAX FILENAME_MAX

#ifndef VERSION
#define VERSION PACKAGE_VERSION
#endif

#if defined(_M_ARM64) || defined(_M_ARM64EC)
#define OPENSC_ARCH_SUFFIX "_arm64"
#else
#define OPENSC_ARCH_SUFFIX ""
#endif

#ifndef OPENSC_PATH
#define OPENSC_PATH "%PROGRAMFILES%\\OpenSC Project\\OpenSC" OPENSC_ARCH_SUFFIX "\\"
#endif

#ifndef CVCDIR
#define CVCDIR OPENSC_PATH "cvc"
#endif

#ifndef DEFAULT_PKCS11_PROVIDER
#define DEFAULT_PKCS11_PROVIDER OPENSC_PATH "pkcs11\\opensc-pkcs11.dll"
#endif
#ifndef DEFAULT_ONEPIN_PKCS11_PROVIDER
#define DEFAULT_ONEPIN_PKCS11_PROVIDER OPENSC_PATH "pkcs11\\onepin-opensc-pkcs11.dll"
#endif

#define PKCS11_THREAD_LOCKING

#ifndef DEFAULT_SM_MODULE
#define DEFAULT_SM_MODULE "smm-local.dll"
#endif

#endif
