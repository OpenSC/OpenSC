#ifndef _SC_TEST_H
#define _SC_TEST_H

#include "libopensc/pkcs15.h"

#ifdef __cplusplus
extern "C" {
#endif

extern struct sc_context *ctx;
extern struct sc_card *card;
struct sc_pkcs15_card;
struct sc_pkcs15_object;

int sc_test_init(int *argc, char *argv[]);
void sc_test_cleanup(void);
void sc_test_print_card(const sc_pkcs15_card_t *);
void sc_test_print_object(const struct sc_pkcs15_object *);

#ifdef __cplusplus
}
#endif

#endif
