#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>

char *getpass(const char *prompt)
{
	static char buf[128];
	size_t i;

	fputs(prompt, stderr);
	fflush(stderr);
	for (i = 0; i < sizeof(buf); i++) {
		buf[i] = _getch();
		if (buf[i] == '\r')
                        break;
	}
	buf[i] = 0;
	fputs("\n", stderr);
        return buf;
}

