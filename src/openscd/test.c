#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assuan.h>

static AssuanError reply_cb(void *opaque, const void *buf, size_t len)
{
	printf("%d\n%s\n", len, buf);
	return 0;
}

int main()
{
	char *infostr, *p;
	char socket[150];
	int r;
	ASSUAN_CONTEXT ctx;
	
	infostr = getenv("OPENSCD_INFO");
	if (infostr == NULL)
		return 0;
	p = strchr(infostr, ':');
	if (p == NULL)
		return 0;
	strncpy(socket, infostr, p - infostr);
	socket[p - infostr] = '\0';
	printf("Socket is: '%s'\n", socket);

	r = assuan_socket_connect(&ctx, socket, -1);
	if (r) {
		fprintf(stderr, "Unable to connect: %s\n", assuan_strerror(r));
		return 1;
	}
	
	r = assuan_transact(ctx, "GET_OBJ 0 400", reply_cb, NULL, NULL, NULL, NULL, NULL);
	if (r) {
		fprintf(stderr, "Unable to transact: %s\n", assuan_strerror(r));
		return 1;
	}
	
}
