#ifndef _OPENSC_WINCONFIG_H
#define _OPENSC_WINCONFIG_H

#include <stdio.h>
#include <windows.h>
#include <sys/timeb.h>

#ifndef strcasecmp
#define strcasecmp stricmp
#endif

#ifndef strncasecmp
#define strncasecmp strnicmp
#endif

#ifndef snprintf
#define snprintf _snprintf
#endif

#ifndef vsnprintf
#define vsnprintf _vsnprintf
#endif

#ifndef isatty
#define isatty _isatty
#endif

#ifndef mkdir
#define mkdir _mkdir
#endif

#ifndef access
#define access _access
#endif

#ifndef R_OK
#define R_OK  4		/* test whether readable.  */
#define W_OK  2		/* test whether writable.  */
#define X_OK  1		/* test whether execubale. */
#define F_OK  0		/* test whether exist.  */
#endif

#define HAVE_GETOPT_H
#define HAVE_IO_H
#define HAVE_GETPASS
#define HAVE_PCSC

/* %windir% is replaced by the path of the Windows directory,
 * this is C:\WINNT or C:\WINDOWS on most systems.
 */
#define OPENSC_CONF_PATH "%windir%\\opensc.conf"

#define SC_PKCS15_PROFILE_DIRECTORY "%windir%"

#define PATH_MAX _MAX_PATH

#ifndef VERSION
#define VERSION "0.8.1"
#endif

/* src/common/getpass.c */
extern char *getpass(const char *prompt);

#endif
