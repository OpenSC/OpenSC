#ifndef _OPENSC_WINCONFIG_H
#define _OPENSC_WINCONFIG_H

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

#define OPENSC_CONF_PATH "C:\\WINNT\\opensc.conf"

#endif
