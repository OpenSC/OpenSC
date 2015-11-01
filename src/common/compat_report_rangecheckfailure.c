#if HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_RANGECHECKFAILURE	/* empty file if __report_rangecheckfailure is available */

// do not fail when linked with /GS dll and when /GS is not available
#ifdef _WIN32
#if defined(_MSC_VER) && (_MSC_VER < 1700)
// only for vs 2012 or later

#include <Windows.h>

__declspec(noreturn) void __cdecl __report_rangecheckfailure()
{
	ExitProcess(1);
}

#endif
#endif
#endif