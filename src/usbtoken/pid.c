#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


#include "usbtoken.h"

char *pidfile;

void pid_exit()
{
	if (pidfile) {
		unlink(pidfile);
		free(pidfile);
	}
}

int pid_init()
{
	int i;

	for (i = 0; i < MAXTOKEN - 1; i++) {
		char buffer[1024];
		int fd;

		snprintf(buffer, sizeof(buffer), PIDFILE, i);
		fd = creat(buffer, 0644);

		if (fd == -1) {
			continue;
		}

		pidfile = strdup(buffer);
		write(fd, buffer, sprintf(buffer, "%d\n", getpid()));
		close(fd);

		usbtoken.slot = i;
		atexit(pid_exit);
		return USBTOKEN_OK;
	}

	return USBTOKEN_ERROR;
}
