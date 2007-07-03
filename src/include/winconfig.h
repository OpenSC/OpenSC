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

#ifndef strnicmp
#define strnicmp _strnicmp
#endif 

#ifndef stricmp
#define stricmp _stricmp
#endif

#ifndef strdup
#define strdup _strdup
#endif

#ifndef fileno
#define fileno _fileno
#endif

#ifndef mkdir
#define mkdir _mkdir
#endif

#ifndef access
#define access _access
#endif

#ifndef unlink
#define unlink _unlink
#endif

#ifndef putenv
#define putenv _putenv
#endif

#ifndef R_OK
#define R_OK  4		/* test whether readable.  */
#define W_OK  2		/* test whether writable.  */
#define X_OK  1		/* test whether execubale. */
#define F_OK  0		/* test whether exist.  */
#endif

#define HAVE_IO_H
#define HAVE_GETPASS
#define HAVE_PCSC

#define PATH_MAX _MAX_PATH

#ifndef VERSION
#define VERSION "0.11.3"
#endif

/* src/common/getpass.c */
extern char *getpass(const char *prompt);

#endif
