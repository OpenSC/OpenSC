#ifndef _OPENSCD_H
#define _OPENSCD_H

#include <opensc/opensc.h>
#include <pthread.h>

#define MAX_CARDS 4

struct openscd_context {
	struct sc_context *ctx;
	char *socket_name;
	int socket_fd;

        int cmd_stuff_ok;
	struct openscd_card {
		sc_card_t *card;
		sc_pkcs15_card_t *p15card;

		struct sc_reader *reader;
		int slot_id;
		int card_id;
                pthread_mutex_t mutex;
	} *cards;
	int card_count;
        int card_id_number;
        pthread_mutex_t card_mutex;

	pthread_t *threads;
        int thread_count;
};

struct openscd_thread_arg {
	struct openscd_context *dctx;
	struct sc_reader *reader;
};

char *mkdtemp(char *template);
void die(int return_code, const char *errmsg, ...);
void command_handler(struct openscd_context *dctx);
void init_cmd_stuff(struct openscd_context *dctx);
void cleanup_cmd_stuff(struct openscd_context *dctx);

#endif	/* _OPENSCD_H */
