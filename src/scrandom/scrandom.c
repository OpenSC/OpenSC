/*
 * $Id$
 *
 * Copyright (C) 2002
 *  Antti Tapaninen <aet@cc.hut.fi>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef _WIN32
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netinet/in.h>
#if !defined(RANDOM_POOL) && !defined(PRNGD_PORT) && !defined(PRNGD_SOCKET)
#define USE_SRANDOM
#include <time.h>
#endif
#include "scrandom.h"

#if defined(PRNGD_SOCKET) || defined(PRNGD_PORT)
#include <signal.h>

#ifndef offsetof
#define offsetof(type, member) ((size_t) &((type *)0)->member)
#endif

typedef void (*mysig_t) (int);

static mysig_t mysignal(int sig, mysig_t act)
{
#ifdef HAVE_SIGACTION
	struct sigaction sa, osa;

	if (sigaction(sig, NULL, &osa) == -1) {
		return (mysig_t) - 1;
	}
	if (osa.sa_handler != act) {
		memset(&sa, 0, sizeof(sa));
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
#if defined(SA_INTERRUPT)
		if (sig == SIGALRM) {
			sa.sa_flags |= SA_INTERRUPT;
		}
#endif
		sa.sa_handler = act;
		if (sigaction(sig, &sa, NULL) == -1) {
			return (mysig_t) - 1;
		}
	}
	return osa.sa_handler;
#else
	return signal(sig, act);
#endif
}
#endif

#if !defined(USE_SRANDOM)

static ssize_t atomicio(ssize_t(*f) (int fd, void *_s, size_t n), int fd, void *_s, size_t n)
{
	char *s = (char *) _s;
	size_t pos = 0;
	ssize_t res;

	while (n > pos) {
		res = (f) (fd, s + pos, n - pos);
		switch (res) {
		case -1:
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
		case 0:
			return res;
		default:
			pos += res;
		}
	}
	return pos;
}

/* Get entropy from:
 * /dev/[u]random or pipe
 * PRNGD/EGD (socket)
 * PRNGD/EGD (port)
 */

static int scrandom_get_bytes(unsigned char *buf, int len)
{
	int fd;

#if defined(RANDOM_POOL)
	fd = open(RANDOM_POOL, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Couldn't open random pool \"%s\": %s\n",
			RANDOM_POOL, strerror(errno));
		return 0;
	}
	if (atomicio(read, fd, buf, len) != len) {
		fprintf(stderr, "Couldn't read from random pool \"%s\": %s\n",
			RANDOM_POOL, strerror(errno));
		close(fd);
		return 0;
	}
	close(fd);
	return 1;
#elif defined(PRNGD_SOCKET)
	int addr_len, rval, errors;
	struct sockaddr_un addr;
	mysig_t old_sigpipe;
	char msg[2];

	memset(&addr, 0, sizeof(addr));
	if (sizeof(PRNGD_SOCKET) > sizeof(addr.sun_path)) {
		fprintf(stderr, "Random pool path is too long");
		return 0;
	}
	if (len > 255) {
		fprintf(stderr, "Too many bytes to read from PRNGD");
		return 0;
	}
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, PRNGD_SOCKET, sizeof(addr.sun_path));
	addr_len = offsetof(struct sockaddr_un, sun_path) + sizeof(PRNGD_SOCKET);
	old_sigpipe = mysignal(SIGPIPE, SIG_IGN);

	errors = rval = 0;
      reopen:
	fd = socket(addr.sun_family, SOCK_STREAM, 0);
	if (fd == -1) {
		fprintf(stderr, "Couldn't create AF_UNIX socket: %s\n", strerror(errno));
		goto done;
	}
	if (connect(fd, (struct sockaddr *) &addr, addr_len) == -1) {
		fprintf(stderr, "Couldn't connect to PRNGD socket \"%s\": %s\n",
			addr.sun_path, strerror(errno));
		goto done;
	}
	/* Send blocking read request to PRNGD */
	msg[0] = 0x02;
	msg[1] = len;

	if (atomicio(write, fd, msg, sizeof(msg)) != sizeof(msg)) {
		if (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			goto reopen;
		}
		fprintf(stderr, "Couldn't write to PRNGD socket: %s\n",
			strerror(errno));
		goto done;
	}
	if (atomicio(read, fd, buf, len) != len) {
		if (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			goto reopen;
		}
		fprintf(stderr, "Couldn't read from PRNGD socket: %s\n",
			strerror(errno));
		goto done;
	}
	rval = 1;
      done:
	mysignal(SIGPIPE, old_sigpipe);
	if (fd != -1) {
		close(fd);
	}
	return rval;
#elif defined(PRNGD_PORT)
	int addr_len, rval, errors;
	struct sockaddr_in addr;
	mysig_t old_sigpipe;
	char msg[2];

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(PRNGD_PORT);
	addr_len = sizeof(struct sockaddr_in);
	old_sigpipe = mysignal(SIGPIPE, SIG_IGN);

	errors = rval = 0;
      reopen:
	fd = socket(addr.sin_family, SOCK_STREAM, 0);
	if (fd == -1) {
		fprintf(stderr, "Couldn't create AF_INET socket: %s\n", strerror(errno));
		goto done;
	}
	if (connect(fd, (struct sockaddr *) &addr, addr_len) == -1) {
		fprintf(stderr, "Couldn't connect to PRNGD port %d: %s\n",
			PRNGD_PORT, strerror(errno));
		goto done;
	}
	/* Send blocking read request to PRNGD */
	msg[0] = 0x02;
	msg[1] = len;

	if (atomicio(write, fd, msg, sizeof(msg)) != sizeof(msg)) {
		if (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			goto reopen;
		}
		fprintf(stderr, "Couldn't write to PRNGD socket: %s\n",
			strerror(errno));
		goto done;
	}
	if (atomicio(read, fd, buf, len) != len) {
		if (errno == EPIPE && errors < 10) {
			close(fd);
			errors++;
			goto reopen;
		}
		fprintf(stderr, "Couldn't read from PRNGD socket: %s\n",
			strerror(errno));
		goto done;
	}
	rval = 1;
      done:
	mysignal(SIGPIPE, old_sigpipe);
	if (fd != -1) {
		close(fd);
	}
	return rval;
#endif
	return 0;
}

#endif

/* Read random data from random data source */

int scrandom_get_data(unsigned char *buf, unsigned int len)
{
#define BLOCK_SIZE 255
	int rv = -1;
#if !defined(USE_SRANDOM)
	unsigned int div, mod, i, bytes;
	unsigned char *p;
#endif
	if (!buf || !len) {
		return -1;
	}
#if !defined(USE_SRANDOM)
	div = len / BLOCK_SIZE;
	mod = len % BLOCK_SIZE;
	p = buf;

	for (i = 0; i <= div; i++) {
		bytes = 0;
		if (div == i) {
			bytes = mod;
		} else {
			bytes = BLOCK_SIZE;
		}
		if (bytes) {
			if (!scrandom_get_bytes(p, bytes)) {
				rv = -1;
			} else {
				if (rv < 0)
					rv = 0;
				rv += bytes;
				p += bytes;
			}
			if (rv < 0) {
				break;
			}
		}
	}
#else
	/* Well, this is only for testing/porting purposes anyway */
	/* FIXME: We could add something like Mersenne Twister -
	   pseudorandom number generator, although that won't either
	   fit into cryptography purposes. So why bother? */

	srandom((len + (unsigned int) time(NULL)));
	for (rv = 0; rv < len; rv++) {
		buf[rv] = (unsigned char) random();
	}
	rv = len;
#endif
	return rv;
#undef BLOCK_SIZE
}

#else

/* Since the above is very *nix specific, we use Window's CryptoAPI
 * random generation instead.
 */

#include "scrandom.h"
#include <windows.h>
#include <wincrypt.h>

int scrandom_get_data(unsigned char *buf, unsigned int len)
{
	HCRYPTPROV hProv = 0;

	if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    		return GetLastError();

	if(!CryptGenRandom(hProv, len, buf))
    		return GetLastError();

	CryptReleaseContext(hProv, 0);

	return 0;
}

#endif
