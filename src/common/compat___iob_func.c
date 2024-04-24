#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_IOB_FUNC	/* empty file if iob_func is available */
#ifdef _WIN32
#if defined(_MSC_VER) && (_MSC_VER >= 1900)
// needed for OpenSSL static link
// only for vs 2015 or later
//
// this is a horrible hack, the correct fix would be to recompile OpenSSL with
// VS 2015 or later. However, since in OpenSC, we don't need OpenSSL to send
// output to any of these buffers, we don't need to cope with runtime errors
// induced by this hack. See https://stackoverflow.com/a/34655235 for details.
//
#pragma comment(lib, "legacy_stdio_definitions.lib")
#include <stdio.h>
FILE * __cdecl __iob_func(void)
{
   static FILE my_iob[3];
   my_iob[0] = *stdin;
   my_iob[1] = *stdout;
   my_iob[2] = *stderr;
   return my_iob;
}
#endif
#endif
#endif
