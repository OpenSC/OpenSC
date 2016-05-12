#include "p11test_helpers.h"
#include "p11test_common.h"

char *convert_byte_string(char *id, unsigned long length)
{
	char *data = malloc(3 * length * sizeof(char) + 1);
	for (unsigned int i = 0; i < length; i++)
		sprintf(&data[i*3], "%02X:", id[i]);
	data[length*3-1] = '\0';
	return data;
}

int open_session(token_info_t *info) {
	CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
	CK_RV rv;

	rv = function_pointer->C_OpenSession(info->slot_id,
		CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR,
		&info->session_handle);

    if(rv != CKR_OK)
        return 1;

    debug_print("Session was successfully created");
    return 0;
}

int group_setup(void **state)
{

    token_info_t * info = malloc(sizeof(token_info_t));

    assert_non_null(info);

    if (load_pkcs11_module(info, library_path)) {
        free(info);
        fail_msg("Could not load module!\n");
    }

    *state = info;
    return 0;
}

int group_teardown(void **state) {

    token_info_t *info = (token_info_t *) *state;
    debug_print("Clearing state after group tests!");
    if(info && info->function_pointer)
        info->function_pointer->C_Finalize(NULL_PTR);

    free(info);
    free(library_path);

    clear_card_info();
    close_pkcs11_module();

    return 0;
}

int clear_token_without_login_setup(void **state) {

    token_info_t *info = (token_info_t *) *state;

    if(initialize_cryptoki(info)) {
        fail_msg("CRYPTOKI couldn't be initialized\n");
    }

    if(open_session(info))
        fail_msg("Could not open session to token!\n");

    return 0;
}

int clear_token_with_user_login_setup(void **state) {
    token_info_t *info = (token_info_t *) *state;
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
    CK_RV rv;

    if(prepare_token(info))
        fail_msg("Could not prepare token.\n");

    debug_print("Logging in to the token!");
	rv = function_pointer->C_Login(info->session_handle, CKU_USER,
		card_info.pin, card_info.pin_length);

    if(rv != CKR_OK)
        fail_msg("Could not login to token with user PIN '%s'\n", card_info.pin);

    return 0;
}

int clear_token_with_user_login_and_import_keys_setup(void **state) {
    token_info_t *info = (token_info_t *) *state;
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
    CK_RV rv;

    if(prepare_token(info))
        fail_msg("Could not prepare token.\n");

    /* Must close sessions and finalize CRYPTOKI and initialize it again because otherwise imported keys won't be found */
    debug_print("Closing all sessions");
    function_pointer->C_CloseAllSessions(info->slot_id);
    function_pointer->C_Finalize(NULL_PTR);

    if(initialize_cryptoki(info)) {
        fail_msg("CRYPTOKI couldn't be initialized\n");
    }

    if(open_session(info)) {
        fail_msg("Could not open session to token!\n");
    }

    rv = function_pointer->C_Login(info->session_handle, CKU_USER, card_info.pin, card_info.pin_length);

    if(rv != CKR_OK)
        fail_msg("Could not login to token with user PIN '%s'\n", card_info.pin);

    return 0;
}

int prepare_token(token_info_t *info) {
    if(initialize_cryptoki(info)) {
        debug_print("CRYPTOKI couldn't be initialized");
        return 1;
    }

    if(open_session(info)) {
        debug_print("Could not open session to token!");
        return 1;
    }

    return 0;
}

int after_test_cleanup(void **state) {

    token_info_t *info = (token_info_t *) *state;
    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;

    debug_print("Logging out from token");
    function_pointer->C_Logout(info->session_handle);

    info->session_handle = 0;
    debug_print("Closing all sessions");
    function_pointer->C_CloseAllSessions(info->slot_id);
    debug_print("Finalize CRYPTOKI");
    function_pointer->C_Finalize(NULL_PTR);
	return 0;
}

int initialize_cryptoki(token_info_t *info) {

    CK_FUNCTION_LIST_PTR function_pointer = info->function_pointer;
    CK_RV rv;

    rv = function_pointer->C_Initialize(NULL_PTR);
    if(rv != CKR_OK){
        fprintf(stderr,"Could not initialize CRYPTOKI!\n");
        return 1;
    }

    if(get_slot_with_card(info)) {
        function_pointer->C_Finalize(NULL_PTR);
        fprintf(stderr,"There is no card present in reader.\n");
        return 1;
    }

    return 0;
}

char id_buffer[11];

const char *get_mechanism_name(int mech_id)
{
	switch (mech_id) {
		case CKM_RSA_PKCS:
			return "CKM_RSA_PKCS";
		case CKM_RSA_X_509:
			return "CKM_RSA_X_509";
		case CKM_ECDSA:
			return "CKM_ECDSA";
		case CKM_ECDSA_SHA1:
			return "CKM_ECDSA_SHA1";
		case CKM_ECDH1_DERIVE:
			return "CKM_ECDH1_DERIVE";
		case CKM_ECDH1_COFACTOR_DERIVE:
			return "CKM_ECDH1_COFACTOR_DERIVE";
		default:
			sprintf(id_buffer, "0x%.8X", mech_id);
			return id_buffer;
	}
}

const char *get_mechanism_flag_name(int mech_id)
{
	switch (mech_id) {
		case CKF_HW:
			return "CKF_HW";
		case CKF_ENCRYPT:
			return "CKF_ENCRYPT";
		case CKF_DECRYPT:
			return "CKF_DECRYPT";
		case CKF_DIGEST:
			return "CKF_DIGEST";
		case CKF_SIGN:
			return "CKF_SIGN";
		case CKF_SIGN_RECOVER:
			return "CKF_SIGN_RECOVER";
		case CKF_VERIFY:
			return "CKF_VERIFY";
		case CKF_VERIFY_RECOVER:
			return "CKF_VERIFY_RECOVER";
		case CKF_GENERATE:
			return "CKF_GENERATE";
		case CKF_GENERATE_KEY_PAIR:
			return "CKF_GENERATE_KEY_PAIR";
		case CKF_WRAP:
			return "CKF_WRAP";
		case CKF_UNWRAP:
			return "CKF_UNWRAP";
		case CKF_DERIVE:
			return "CKF_DERIVE";
		case CKF_EC_F_P:
			return "CKF_EC_F_P";
		case CKF_EC_F_2M:
			return "CKF_EC_F_2M";
		case CKF_EC_NAMEDCURVE:
			return "CKF_EC_NAMEDCURVE";
		case CKF_EC_UNCOMPRESS:
			return "CKF_EC_UNCOMPRESS";
		case CKF_EC_COMPRESS:
			return "CKF_EC_COMPRESS";
		default:
			sprintf(id_buffer, "0x%.8X", mech_id);
			return id_buffer;
	}
}
