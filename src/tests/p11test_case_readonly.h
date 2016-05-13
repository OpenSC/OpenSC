#include "p11test_case_common.h"

#define SHORT_MESSAGE_TO_SIGN "Simple message for signing & verifying.\n"
#define BUFFER_SIZE		4096

void readonly_tests(void **state);
int encrypt_decrypt_test(test_cert_t *o, token_info_t *info, test_mech_t *mech);
int sign_verify_test(test_cert_t *o, token_info_t *info, test_mech_t *mech, CK_ULONG message_length);

