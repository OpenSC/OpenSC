
#ifndef _SC_TEST_H

extern struct sc_context *ctx;
extern struct sc_card *card;

int sc_test_init(int *argc, char *argv[]);
void sc_test_cleanup();

#endif
