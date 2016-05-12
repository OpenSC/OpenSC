#ifndef P11TEST_HELPERS_H
#define P11TEST_HELPERS_H

#include "p11test_loader.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

char* library_path;

char *convert_byte_string(char *id, unsigned long length);

int open_session(token_info_t *info);
int initialize_cryptoki(token_info_t *info);
int prepare_token(token_info_t *info);

int group_setup(void **state);
int group_teardown(void **state);

int after_test_cleanup(void **state);
int clear_token_with_user_login_setup(void **state);
int clear_token_without_login_setup(void **state);
int clear_token_with_user_login_and_import_keys_setup(void **state);
int init_token_with_default_pin(token_info_t *info);

const char *get_mechanism_name(int mech_id);
const char *get_mechanism_flag_name(int flag_id);

#endif //P11TEST_HELPERS_H
