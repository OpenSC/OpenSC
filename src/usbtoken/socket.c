#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "usbtoken.h"

#define MSG_ERROR -1
#define MSG_OK 0
#define MSG_TRANSMIT 3
#define MSG_LOCK 4
#define MSG_UNLOCK 5

char *socketpath;

void socket_exit()
{
	if (socketpath) {
		unlink(socketpath);
		free(socketpath);
	}
}

int socket_init()
{
	int rc;
	struct sockaddr_un ua;
	int ualen;
	mode_t oldmask;

	usbtoken.unixfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (usbtoken.unixfd == -1) {
		syslog(LOG_ERR,
		       "socket_init: socket failed: %s, aborting!\n",
		       strerror(errno));
		return USBTOKEN_ERROR;
	}

	bzero(&ua, sizeof(ua));
	ua.sun_family = AF_UNIX;
	snprintf(ua.sun_path, sizeof(ua.sun_path), SOCKET, usbtoken.slot);

	socketpath = strdup(ua.sun_path);
	unlink(socketpath);
	atexit(socket_exit);

	ualen = sizeof(ua.sun_family) + strlen(ua.sun_path);
	oldmask = umask(0);
	rc = bind(usbtoken.unixfd, (struct sockaddr *) &ua, ualen);
	umask(oldmask);

	/* some error */
	if (rc == -1) {
		syslog(LOG_DEBUG,
		       "socket_init: bind on %s failed: %s(%d), aborting!\n",
		       ua.sun_path, strerror(errno), errno);
		return USBTOKEN_ERROR;
	}

	rc = listen(usbtoken.unixfd, 1);
	if (rc == -1) {
		syslog(LOG_DEBUG,
		       "socket_init: listen failed: %s(%d), aborting!\n",
		       strerror(errno), errno);
		return USBTOKEN_ERROR;
	}

	rc = fcntl(usbtoken.unixfd, F_SETFL, O_NONBLOCK);
	if (rc == -1) {
		syslog(LOG_DEBUG,
		       "socket_init: fcntl failed: %s(%d), aborting!\n",
		       strerror(errno), errno);
		return USBTOKEN_ERROR;
	}

	return USBTOKEN_OK;
}

int socket_accept()
{
	int rc;

	rc = accept(usbtoken.unixfd, NULL, 0);
	if (rc == -1) {
		syslog(LOG_ERR, "socket_accept: accept failed: %s(%d)",
		       strerror(errno), errno);
		return USBTOKEN_ERROR;
	}
	if (usbtoken.connfd) {
		close(rc);
		return USBTOKEN_OK;
	}
	usbtoken.connfd = rc;

	rc = write(usbtoken.connfd, usbtoken.atr, usbtoken.atrlen);
	if (rc == -1) {
		syslog(LOG_ERR,
		       "socket_accept: write failed: %s(%d)",
		       strerror(errno), errno);
		return USBTOKEN_ERROR;
	}
	return USBTOKEN_OK;
}

int socket_hangup()
{
	int rc;

	rc = close(usbtoken.connfd);
	usbtoken.connfd = 0;
	return USBTOKEN_OK;
}

int unix_write(uint8_t msg, int size)
{
	int rc;

	rc = write(usbtoken.connfd, &msg, size);
	if (rc == -1) {
		syslog(LOG_ERR, "unix_write: write failed: %s(%d)",
		       strerror(errno), errno);
		return USBTOKEN_ERROR;
	}
	return USBTOKEN_OK;
}

int socket_xmit()
{
	uint8_t buf_read[1024];
	int rc, len_read;

	rc = read(usbtoken.connfd, buf_read, sizeof(buf_read));
	if (rc == -1) {
		syslog(LOG_ERR, "socket_xmit: read failed: %s(%d)",
		       strerror(errno), errno);
		return USBTOKEN_ERROR;
	}
	len_read = rc;

	if (buf_read[0] == MSG_TRANSMIT) {
		uint8_t buf_write[1024];
		int len_write;
		len_write = sizeof(buf_write) - 1;

		rc = t1_process(&buf_read[1], len_read - 1,
				&buf_write[1], &len_write);
		if (rc != USBTOKEN_OK)
			return rc;
		buf_write[0] = MSG_TRANSMIT;

		rc = write(usbtoken.connfd, buf_write, len_write + 1);
		if (rc == -1) {
			syslog(LOG_ERR,
			       "socket_xmit: write failed: %s(%d)",
			       strerror(errno), errno);
			return USBTOKEN_ERROR;
		}
		return USBTOKEN_OK;
	}

	/* all other commands are single byte commands */
	if (len_read != 1) {
		syslog(LOG_ERR, "socket_xmit: recv returned: %d",
		       len_read);
		return USBTOKEN_ERROR;
	}

	if (buf_read[0] == MSG_LOCK) {
		return unix_write(MSG_OK, 1);
	}

	if (buf_read[0] == MSG_UNLOCK) {
		return unix_write(MSG_OK, 1);
	}

	return unix_write(MSG_ERROR, 1);
}
