#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdarg.h>
#include <assuan.h>
#include <opensc/opensc.h>
#include <opensc/pkcs15.h>
#include "openscd.h"

struct openscd_context *dctx = NULL;

int opt_pipe = 0;

void cleanup(void)
{
	if (dctx == NULL)
		return;
	cleanup_cmd_stuff(dctx);
	if (dctx->ctx != NULL)
		sc_release_context(dctx->ctx);
	if (dctx->socket_name != NULL) {
		char *p;
		
		if (dctx->socket_fd >= 0)
			close(dctx->socket_fd);
		unlink(dctx->socket_name);
		if ((p = strrchr(dctx->socket_name, '/')) != NULL) {
			*p = '\0';
			rmdir(dctx->socket_name);
		}
		free(dctx->socket_name);
	}
	free(dctx);
	dctx = NULL;
}

void die(int return_code, const char *errmsg, ...)
{
	if (errmsg != NULL) {
		va_list ap;
		char *p = (char *) malloc(strlen(errmsg)+2);
		
		strcpy(p, errmsg);
		strcat(p, "\n");
		va_start(ap, errmsg);
		vfprintf(stderr, p, ap);
		free(p);
		va_end(ap);
	}
	cleanup();
	
	exit(return_code);
}

void setup_socket(void)
{
	int fd;
	const char *socket_dir = "/tmp/openscd-XXXXXX";
	const char *socket_file = "socket";
	char *socket_name;
	struct sockaddr_un serv_addr;

	socket_name = (char *) malloc(strlen(socket_dir)+strlen(socket_file)+2);
	assert(socket_name != NULL);
	strcpy(socket_name, socket_dir);

	if (mkdtemp(socket_name) == NULL)
		die(1, "Unable to create directory '%s': %s\n",
		    socket_name, strerror(errno));
	strcat(socket_name, "/");
	strcat(socket_name, socket_file);
	if (strlen(socket_name) + 1 >= sizeof(serv_addr.sun_path))
		die(1, "Name of socket too long\n");
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1)
		die(1, "Can't create socket: %s\n", strerror(errno));
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sun_family = AF_UNIX;
	strcpy(serv_addr.sun_path, socket_name);
	if (bind(fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == -1) {
		close(fd);
		die(1, "Error binding socket to '%s': %s\n",
		    serv_addr.sun_path, strerror(errno));
	}
	if (listen(fd, 5) == -1) {
		close(fd);
		die(1, "listen() failed: %s\n", strerror(errno));
	}
	dctx->socket_name = strdup(socket_name);
	dctx->socket_fd = fd;
}

void do_fork(void)
{
	int pid;
	
	pid = fork();
	if (pid == (pid_t) -1)
		die(1, "fork() failed: %s\n", strerror(errno));
	if (pid) {
		char *infostr;
		int n = strlen(dctx->socket_name) + 40;
				
		infostr = (char *) malloc(n);
		if (snprintf(infostr, n, "OPENSCD_INFO=%s:%lu:1",
			     dctx->socket_name, (ulong) pid) < 0) {
			kill(pid, SIGTERM);
			die(1, "Something went wrong\n");
		}
		printf("%s; export OPENSCD_INFO;\n", infostr);
		free(infostr);
		
		free(dctx->socket_name);
		dctx->socket_name = NULL;		
		die(0, NULL);
	}
}

void init_dctx(void)
{
	int r;
	
	r = sc_establish_context(&dctx->ctx, "openscd");
	if (r != 0)
		die(1, "Unable to establish context: %s", sc_strerror(r));
	init_cmd_stuff(dctx);
}

int main(int argc, char *argv[])
{
	dctx = (struct openscd_context *) malloc(sizeof(struct openscd_context));
	assert(dctx != NULL);
	memset(dctx, 0, sizeof(struct openscd_context));
	
	if (!opt_pipe) {
		setup_socket();
		do_fork();
	}

        init_dctx();

	atexit(cleanup);
	command_handler(dctx);

	return 0;
}
