#ifndef P11TEST_HELPERS_H
#define P11TEST_HELPERS_H
#include "p11test_common.h"

#define DEFAULT_PIN		"123456"

token_info_t token;

int group_setup(void **state);
int group_teardown(void **state);

int user_login_setup(void **state);
int after_test_cleanup(void **state);

int token_setup(void **state);
int token_cleanup(void **state);

#endif //P11TEST_HELPERS_H
