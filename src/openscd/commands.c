#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include <string.h>

#include <assuan.h>
#include <opensc/opensc.h>
#include <opensc/log.h>
#include <opensc/pkcs15.h>
#include "openscd.h"

static struct openscd_card * find_card(struct openscd_context *dctx,
				       struct sc_reader *reader,
				       int slot_id)
{
	int i;

	for (i = 0; i < dctx->card_count; i++) {
		struct openscd_card *dcard = dctx->cards + i;

		if (dcard->reader == reader && dcard->slot_id == slot_id)
                        return dcard;
	}
        return NULL;
}

static struct openscd_card * find_card_by_id(struct openscd_context *dctx,
					     int card_id)
{
	int i;

	for (i = 0; i < dctx->card_count; i++) {
		struct openscd_card *dcard = dctx->cards + i;

		if (dcard->card_id == card_id)
                        return dcard;
	}
        return NULL;
}

static void card_inserted(struct openscd_context *dctx,
			  struct sc_reader *reader,
			  int slot_id)
{
        int n = dctx->card_count;
        int r;
	struct sc_card *card;
        struct sc_pkcs15_card *p15card;

	dctx->cards = (struct openscd_card *) realloc(dctx->cards, (n + 1) * sizeof(struct openscd_card));
	assert(dctx->cards != NULL);
        memset(dctx->cards + n, 0, sizeof(struct openscd_card));

	dctx->cards[n].reader = reader;
	dctx->cards[n].slot_id = slot_id;

	r = sc_connect_card(reader, slot_id, &card);
	if (r) {
		sc_error(dctx->ctx, "Unable to connect to card: %s\n", sc_strerror(r));
	} else {
		dctx->cards[n].card = card;
		r = sc_pkcs15_bind(card, &p15card);
		if (r) {
			sc_error(dctx->ctx, "Error with PKCS #15 card: %s\n", sc_strerror(r));
		} else
			dctx->cards[n].p15card = p15card;
	}
	dctx->cards[n].card_id = dctx->card_id_number;
        pthread_mutex_init(&dctx->cards[n].mutex, NULL);
	dctx->card_id_number++;
	dctx->card_count++;
        fprintf(stderr, "Card %d inserted.\n", dctx->cards[n].card_id);
}

static void card_removed(struct openscd_context *dctx,
			 struct openscd_card *dcard)
{
	int idx;

	fprintf(stderr, "Card %d removed.\n", dcard->card_id);
	if (dcard->p15card != NULL) {
		sc_pkcs15_unbind(dcard->p15card);
		dcard->p15card = NULL;
	}
	if (dcard->card != NULL) {
		/* This should fail... */
		sc_disconnect_card(dcard->card, SC_DISCONNECT_AND_EJECT);
		dcard->card = NULL;
	}
	for (idx = 0; idx < dctx->card_count; idx++) {
		if (dctx->cards + idx == dcard) {
			memmove(dctx->cards, dctx->cards + idx + 1,
                                dctx->card_count - (idx + 1));
			break;
		}
	}
	assert(idx != dctx->card_count);
        dctx->card_count--;
	dctx->cards = (struct openscd_card *) realloc(dctx->cards, dctx->card_count * sizeof(struct openscd_card));
        assert(dctx->cards != NULL || dctx->card_count == 0);
}

static int cmd_list_readers(ASSUAN_CONTEXT actx, char *line)
{
	struct openscd_context *dctx = (struct openscd_context *) assuan_get_pointer(actx);
	int i, r;

	for (i = 0; i < dctx->ctx->reader_count; i++) {
		char line[80];

		snprintf(line, sizeof(line), "%s", dctx->ctx->reader[i]->name);
		r = assuan_send_data(actx, line, strlen(line));
		if (r)
			return r;
	}

	return 0;
}

static int cmd_list_cards(ASSUAN_CONTEXT actx, char *line)
{
	struct openscd_context *dctx = (struct openscd_context *) assuan_get_pointer(actx);
	int i, r = 0;

        pthread_mutex_lock(&dctx->card_mutex);
	for (i = 0; i < dctx->card_count; i++) {
		char line[80];

		snprintf(line, sizeof(line), "Card%d '%s' %d", dctx->cards[i].card_id,
			 dctx->cards[i].reader->name, dctx->cards[i].slot_id);
		r = assuan_send_data(actx, line, strlen(line));
		if (r)
			break;
	}
        pthread_mutex_unlock(&dctx->card_mutex);
	return 0;
}

static int cmd_get_objects(ASSUAN_CONTEXT actx, char *line)
{
	struct openscd_context *dctx = (struct openscd_context *) assuan_get_pointer(actx);
        struct openscd_card *dcard;
	int card_id, obj_type, i, obj_count, r = 0;
        struct sc_pkcs15_object *objs[32];

	r = sscanf(line, "%X %X", &card_id, &obj_type);
	if (r != 2)
		return ASSUAN_Invalid_Command;
	pthread_mutex_lock(&dctx->card_mutex);
	dcard = find_card_by_id(dctx, card_id);
        if (dcard != NULL)
		pthread_mutex_lock(&dcard->mutex);
        pthread_mutex_unlock(&dctx->card_mutex);
	if (dcard == NULL)
		return ASSUAN_Invalid_Card;
	if (dcard->p15card == NULL) {
                r = ASSUAN_No_PKCS15_App;
		goto ret;
	}
	obj_count = sc_pkcs15_get_objects(dcard->p15card, obj_type, objs, 32);
	if (obj_count < 0) {
                /* FIXME */
		r = ASSUAN_Card_Error;
                goto ret;
	}
	for (i = 0; i < obj_count; i++) {
		char *line;
		
		line = (char *) malloc(objs[i]->der.len * 2 + 2);
		if (line == NULL)
			return ASSUAN_Out_Of_Core;
		sc_bin_to_hex(objs[i]->der.value, objs[i]->der.len,
			      line, objs[i]->der.len * 2 + 2, 0);
		strcat(line, "\n");
		r = assuan_send_data(actx, line, strlen(line));
		free(line);
		if (r)
			return r;
	}
ret:
	pthread_mutex_unlock(&dcard->mutex);
	return r;
}

static struct {
	const char *name;
	int (*handler)(ASSUAN_CONTEXT, char *line);
} ctable[] = {
	{ "LISTR",	cmd_list_readers },
	{ "LISTC",      cmd_list_cards },
	{ "GET_OBJ",    cmd_get_objects },
	{ "INPUT",      NULL },
	{ "OUTPUT",     NULL },
	{ NULL }
};

static int register_commands(ASSUAN_CONTEXT assuan_ctx)
{
	int i, j, r;
	
	for (i = j = 0; ctable[i].name != NULL; i++) {
		r = assuan_register_command(assuan_ctx, 
					    ctable[i].name, ctable[i].handler);
		if (r)
			return r;
	}
	assuan_set_hello_line(assuan_ctx, "openscd ready");

#if 0
	assuan_register_reset_notify (ctx, reset_notify);
	assuan_register_option_handler (ctx, option_handler);
#endif
	return 0;
}

static void * sc_thread(void *arg)
{
        struct openscd_thread_arg *targ = (struct openscd_thread_arg *) arg;
	struct openscd_context *dctx = targ->dctx;
        struct sc_reader *reader = targ->reader;
	struct sc_context *ctx = dctx->ctx;
        const int sleep_time = 200;
        int r;

        free(arg);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	for (;;) {
		struct openscd_card *dcard;

		r = sc_detect_card_presence(reader, 0);
		if (r < 0) {
			sc_perror(ctx, r, "Unable to detect card presence");
			return NULL;
		}
		pthread_testcancel();
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		pthread_mutex_lock(&dctx->card_mutex);
		dcard = find_card(dctx, reader, 0);
		if (r == 1) {
			if (dcard == NULL)
				card_inserted(dctx, reader, 0);
		} else {
			if (dcard != NULL) {
                                pthread_mutex_lock(&dcard->mutex);
				card_removed(dctx, dcard);
			}
		}
		pthread_mutex_unlock(&dctx->card_mutex);
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		usleep(sleep_time);
	}
}

void init_cmd_stuff(struct openscd_context *dctx)
{
	pthread_mutex_init(&dctx->card_mutex, NULL);

	dctx->cmd_stuff_ok = 1;
	dctx->card_count = 0;
        dctx->thread_count = 0;
}

void cleanup_cmd_stuff(struct openscd_context *dctx)
{
	int i;

	if (!dctx->cmd_stuff_ok)
		return;
	for (i = 0; i < dctx->thread_count; i++) {
		pthread_cancel(dctx->threads[i]);
		pthread_join(dctx->threads[i], NULL);
	}
	free(dctx->threads);

	pthread_mutex_destroy(&dctx->card_mutex);

	for (i = 0; i < dctx->card_count; i++) {
		struct openscd_card *dcard = dctx->cards + i;

		if (dcard->p15card != NULL)
			sc_pkcs15_unbind(dcard->p15card);
		if (dcard->card != NULL)
			sc_disconnect_card(dcard->card, SC_DISCONNECT_AND_RESET);
	}
	if (dctx->cards != NULL)
		free(dctx->cards);
}

static void spawn_reader_threads(struct openscd_context *dctx)
{
	int i, r, count;

	if (dctx->ctx->reader_count == 0)
		return;
	count = dctx->ctx->reader_count;
	dctx->threads = (pthread_t *) calloc(count, sizeof(pthread_t));
	assert(dctx->threads != NULL);
	for (i = 0; i < count; i++) {
		struct openscd_thread_arg *arg;

		arg = (struct openscd_thread_arg *) malloc(sizeof(struct openscd_thread_arg));
		assert(arg != NULL);
		arg->dctx = dctx;
		arg->reader = dctx->ctx->reader[i];
		r = pthread_create(dctx->threads + i, NULL, sc_thread, arg);
		if (r) {
			free(arg);
			free(dctx->threads);
			/* FIXME: Kill all the spawned threads */
			die(1, "Unable to spawn thread: %s\n", strerror(errno));
		}
	}
	dctx->thread_count = count;
}

void command_handler(struct openscd_context *dctx)
{
	int r;
	ASSUAN_CONTEXT assuan_ctx;

        spawn_reader_threads(dctx);

	if (dctx->socket_fd <= 0) {
		int fds[2];

		fds[0] = 0;
                fds[1] = 1;
		r = assuan_init_pipe_server(&assuan_ctx, fds);
	} else
		r = assuan_init_socket_server(&assuan_ctx, dctx->socket_fd);
	if (r)
		die(1, "Failed to initialize the server: %s\n",
		    assuan_strerror((AssuanError) r));
	r = register_commands(assuan_ctx);
	if (r)
		die(1, "Failed to register commands with Assuan: %s\n",
		    assuan_strerror((AssuanError) r));

	assuan_set_pointer(assuan_ctx, dctx);

	for (;;) {
		r = assuan_accept(assuan_ctx);
		if (r == -1)
			break;
		if (r) {
			sc_error(dctx->ctx, "Assuan accept problem: %s\n", assuan_strerror((AssuanError) r));
			break;
		}
		r = assuan_process(assuan_ctx);
		if (r) {
			sc_error(dctx->ctx, "Assuan processing failed: %s\n", assuan_strerror((AssuanError) r));
			continue;
		}
	}
	assuan_deinit_server(assuan_ctx);
}
