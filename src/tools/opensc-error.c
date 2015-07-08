#include <string.h>
#include <time.h>
#include <libopensc/opensc.h>

#ifdef _WIN32
#include <windows.h>
#define sleep(i) Sleep(i*1000)
#endif

#define CHECK(s, r) if (r) { \
  fprintf(stderr, "Error in %s: %s (%d)\n", s, sc_strerror(r), r); \
  return(r); \
}

// copied from util.c

int
is_string_valid_atr(const char *atr_str)
{
        unsigned char atr[SC_MAX_ATR_SIZE];
        size_t atr_len = sizeof(atr);

        if (sc_hex_to_bin(atr_str, atr, &atr_len))
                return 0;
        if (atr_len < 2)
                return 0;
        if (atr[0] != 0x3B && atr[0] != 0x3F)
                return 0;
        return 1;
}

int
util_connect_card(sc_context_t *ctx, sc_card_t **cardp,
                 const char *reader_id, int do_wait, int verbose)
{
        struct sc_reader *reader = NULL, *found = NULL;
        struct sc_card *card = NULL;
        int r;

        if (do_wait) {
                unsigned int event;

                if (sc_ctx_get_reader_count(ctx) == 0) {
                        fprintf(stderr, "Waiting for a reader to be attached...\n");
                        r = sc_wait_for_event(ctx, SC_EVENT_READER_ATTACHED, &found, &event, -1, NULL);
                        if (r < 0) {
                                fprintf(stderr, "Error while waiting for a reader: %s\n", sc_strerror(r));
                                return 3;
                        }
                        r = sc_ctx_detect_readers(ctx);
                        if (r < 0) {
                                fprintf(stderr, "Error while refreshing readers: %s\n", sc_strerror(r));
                                return 3;
                        }
                }
                fprintf(stderr, "Waiting for a card to be inserted...\n");
                r = sc_wait_for_event(ctx, SC_EVENT_CARD_INSERTED, &found, &event, -1, NULL);
                if (r < 0) {
                        fprintf(stderr, "Error while waiting for a card: %s\n", sc_strerror(r));
                        return 3;
                }
                reader = found;
        }
        else if (sc_ctx_get_reader_count(ctx) == 0) {
                fprintf(stderr, "No smart card readers found.\n");
                return 1;
        }
        else   {
                if (!reader_id) {
                        unsigned int i;
                        /* Automatically try to skip to a reader with a card if reader not specified */
                        for (i = 0; i < sc_ctx_get_reader_count(ctx); i++) {
                                reader = sc_ctx_get_reader(ctx, i);
                                if (sc_detect_card_presence(reader) & SC_READER_CARD_PRESENT) {
                                        fprintf(stderr, "Using reader with a card: %s\n", reader->name);
                                        goto autofound;
                                }
                        }
                        /* If no reader had a card, default to the first reader */
                        reader = sc_ctx_get_reader(ctx, 0);
                }
                else {
                        /* If the reader identifier looks like an ATR, try to find the reader with that card */
                        if (is_string_valid_atr(reader_id))   {
                                unsigned char atr_buf[SC_MAX_ATR_SIZE * 3];
                                size_t atr_buf_len = sizeof(atr_buf);
                                unsigned int i;

                                sc_hex_to_bin(reader_id, atr_buf, &atr_buf_len);
                                /* Loop readers, looking for a card with ATR */
                                for (i = 0; i < sc_ctx_get_reader_count(ctx); i++) {
                                        struct sc_reader *rdr = sc_ctx_get_reader(ctx, i);
                                        if (!(sc_detect_card_presence(rdr) & SC_READER_CARD_PRESENT))
                                                continue;
                                        else if (rdr->atr.len != atr_buf_len)
                                                continue;
                                        else if (memcmp(rdr->atr.value, atr_buf, rdr->atr.len))
                                                continue;

                                        fprintf(stderr, "Matched ATR in reader: %s\n", rdr->name);
                                        reader = rdr;
                                        goto autofound;
                                }
                        }
                        else   {
                                char *endptr = NULL;
                                unsigned int num;

                                errno = 0;
                                num = strtol(reader_id, &endptr, 0);
                                if (!errno && endptr && *endptr == '\0')
                                        reader = sc_ctx_get_reader(ctx, num);
                                else
                                        reader = sc_ctx_get_reader_by_name(ctx, reader_id);
                        }
                }
autofound:
                if (!reader) {
                        fprintf(stderr, "Reader \"%s\" not found (%d reader(s) detected)\n",
                                        reader_id, sc_ctx_get_reader_count(ctx));
                        return 1;
                }

                if (sc_detect_card_presence(reader) <= 0) {
                        fprintf(stderr, "Card not present.\n");
                        return 3;
                }
        }

        if (verbose)
                printf("Connecting to card in reader %s...\n", reader->name);
        r = sc_connect_card(reader, &card);
        if (r < 0) {
                fprintf(stderr, "Failed to connect to card: %s\n", sc_strerror(r));
                return 1;
        }

        if (verbose)
                printf("Using card driver %s.\n", card->driver->name);

        r = sc_lock(card);
        if (r < 0) {
                fprintf(stderr, "Failed to lock card: %s\n", sc_strerror(r));
                sc_disconnect_card(card);
                return 1;
        }

        *cardp = card;
        return 0;
}

// end of copied util.c

void print_timestamp(char *s) {
  time_t rawtime;
  struct tm * timeinfo;

  time(&rawtime);
  timeinfo = localtime(&rawtime);
  printf("TIMESTAMP %s: %s", s, asctime(timeinfo));
  fflush(stdout);
}

int main(int argc, char *argv[]) {
  sc_context_t *ctx = NULL;
  sc_card_t *card = NULL;
  sc_context_param_t ctx_param;
  char *opt_reader = NULL;
  int opt_wait = 0;
  int verbose = 1;
  int r;
  char tmp[SC_MAX_ATR_SIZE*3];

  // prepare the params
  memset(&ctx_param, 0, sizeof(ctx_param));
  ctx_param.ver      = 0;
  ctx_param.app_name = "opensc-error";

  print_timestamp("start");

  // connect to the opensc context
  r = sc_context_create(&ctx, &ctx_param);
  CHECK("sc_context_create", r);
  print_timestamp("context created");

  ctx->enable_default_driver = 1;

  // util_connect_card copied from util.c => connect to the first driver
  // you can specify a reader in opt_reader, I have only one => no problem
  // sc_connect is done inside it
  r = util_connect_card(ctx, &card, opt_reader, opt_wait, verbose);
  CHECK("util_connect_card", r);
  print_timestamp("connect and lock adquired");

  // sleep 10 seconds
  sleep(10);

  // print the atr
  sc_bin_to_hex(card->atr.value, card->atr.len, tmp, sizeof(tmp) - 1, ':');
  fprintf(stdout,"%s\n",tmp);

  // reset the card (lock is lost in pcsc-lite)
  r = sc_reset(card, 1); 
  print_timestamp("reset done");

  // sleep 10 seconds
  sleep(10);

  // unlock
  r= sc_unlock(card);
  CHECK("sc_unlock", r);
  print_timestamp("lock released");

  // sleep after unlock => check the problem
  sleep(10);

  // disconnect
  r = sc_disconnect_card(card);
  CHECK("sc_disconnect_card", r);

  // release
  r = sc_release_context(ctx);
  CHECK("sc_release_context", r);
  print_timestamp("disconnected");
}
