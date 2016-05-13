#ifndef P11TEST_LOADER_H
#define P11TEST_LOADER_H

#include <dlfcn.h>
#include "p11test_helpers.h"

int load_pkcs11_module(token_info_t * info, const char* path_to_pkcs11_library);
int get_slot_with_card(token_info_t * info);
void close_pkcs11_module();


#endif //P11TEST_LOADER_H
