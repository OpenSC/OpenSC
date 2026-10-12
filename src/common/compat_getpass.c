#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef HAVE_GETPASS	/* empty file if getpass is available */
#include <stdio.h>

#include "compat_getpass.h"

#ifdef _WIN32
#include <conio.h>
#else
#include <stdio.h>
#include <termios.h>
#include <unistd.h>

int _getch(void)
{
	struct termios old, mute;
	int c;

	tcgetattr(STDIN_FILENO, &old);
	mute = old;
	mute.c_lflag &= ~(ICANON|ECHO);

	if (0 != tcsetattr(STDIN_FILENO, TCSANOW, &mute)) {
		/* XXX an error happened */
		/* We prefer to print the password, i.e. ignore the error,
		 * rather than to deny the service, i.e. return something like '\0' */
	}

	c = getchar();

	tcsetattr(STDIN_FILENO, TCSANOW, &old);

	return c;
}
#endif

char *getpass(const char *prompt)
{
	static char buf[128];
	size_t i = 0;
	int c;

	if (prompt) {
		fputs(prompt, stderr);
		fflush(stderr);
	}
	while (i < sizeof(buf) - 1) {
		c = _getch();
		if (c == '\r' || c == '\n' || c == EOF)
			break;
		if (c == '\b' || c == 127) {
			if (i > 0)
				i--;
			continue;
		}
		buf[i++] = (char) c;
	}
	buf[i] = '\0';
	fputs("\n", stderr);
	return buf;
}
#endif	/* HAVE_GETPASS */
