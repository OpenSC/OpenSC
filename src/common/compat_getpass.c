#include "config.h"

#ifndef HAVE_GETPASS	/* empty file if getpass is available */
#include <stdio.h>

#include "compat_getpass.h"

#ifdef _WIN32
char *getpass(const char *prompt)
{
	static char buf[128];
	size_t i;

	fputs(prompt, stderr);
	fflush(stderr);
	for (i = 0; i < sizeof(buf) - 1; i++) {
		buf[i] = _getch();
		if (buf[i] == '\r')
			break;
	}
	buf[i] = 0;
	fputs("\n", stderr);
	return buf;
}
#else
#error Need getpass implementation
#endif
#endif	/* HAVE_GETPASS */
