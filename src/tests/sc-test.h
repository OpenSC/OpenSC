#ifndef _SC_TEST_H
#define _SC_TEST_H

extern struct sc_context *ctx;
extern struct sc_card *card;
struct sc_pkcs15_object;

int sc_test_init(int *argc, char *argv[]);
void sc_test_cleanup();
void sc_test_print_object(const struct sc_pkcs15_object *);

#endif
